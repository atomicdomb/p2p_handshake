//Protocol Constants
pub const ZERO_HEADER: &[u8; 3] = &[194, 128, 128];
pub const ETH_PROTOCOL_VERSION: usize = 5;

//Imports
use crate::hmac::HMac;
use std::ops::BitAnd;
use bytes::{Bytes, BytesMut};
use byteorder::{BigEndian, ByteOrder};
use ethereum_types::{H128, H256};
use std::net::{Ipv4Addr, SocketAddrV4};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use rlp::{Decodable, Encodable,Rlp, RlpStream};
use aes::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use concat_kdf::Error;
use hmac::{Hmac, Mac as h_mac};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

pub type Aes128 = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256 = ctr::Ctr64BE<aes::Aes256>;

pub async fn perform_eth_handshake(mut stream: TcpStream, node_public_key: PublicKey) -> Result<(),std::io::Error> {
    //Set up private keys, ephermeral keys, gen auth bytes etc..
    println!("Starting handshake...");
    let nonce = H256::random();
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
    let ephemeral_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let auth_encrypted = gen_auth_bytes(private_key,node_public_key,ephemeral_key,nonce);
    let auth_mess = Bytes::copy_from_slice(&auth_encrypted[..]);

    //Send starting message and parse response
    stream.write(&auth_encrypted).await?;
    println!("Auth message sent to node...");
    let mut buf = [0_u8; 1024];
    let resp = stream.read(&mut buf).await?;
    let mut bytes_used = 0u16;
    let (decrypted,auth_received) = decrypt_data(&mut buf, &mut bytes_used, &private_key);
    println!("Hello Response from Node as bytes: {:?}", decrypted);

    //Now we are going to parse the response and check the MACs
    let rlp = Rlp::new(decrypted);
    let recipient_ephemeral_pubk_raw: Vec<_> = rlp.val_at(0).unwrap();
    let mut mini_buf = [4_u8; 65];
    mini_buf[1..].copy_from_slice(&recipient_ephemeral_pubk_raw);
    let recipient_ephemeral_pubk =PublicKey::from_slice(&mini_buf).unwrap();

    // recipient nonce
    let recipient_nonce_raw: Vec<_> = rlp.val_at(1).unwrap();
    let recipient_nonce = H256::from_slice(&recipient_nonce_raw);

    // ephemeral-key
    let ephemeral_key = H256::from_slice(
        &secp256k1::ecdh::shared_secret_point(
            &recipient_ephemeral_pubk,
            &ephemeral_key,
        )[..32],
    );

    let keccak_nonce = create_hash(&[recipient_nonce.as_ref(), nonce.as_ref()]);
    let shared_secret = create_hash(&[ephemeral_key.as_ref(), keccak_nonce.as_ref()]);
    let aes_secret = create_hash(&[ephemeral_key.as_ref(), shared_secret.as_ref()]);
    let mac_secret = create_hash(&[ephemeral_key.as_ref(), aes_secret.as_ref()]);
    let iv = H128::default();

    // egress-mac
    let mut egress_mac = HMac::new(mac_secret);
    egress_mac.update((mac_secret ^ recipient_nonce).as_bytes());
    egress_mac.update(auth_mess.as_ref());
    let egress_aes = Aes256::new(aes_secret.as_ref().into(),iv.as_ref().into());

    // ingress-mac
    let mut ingress_mac = HMac::new(mac_secret);
    ingress_mac.update((mac_secret ^ nonce).as_bytes());
    ingress_mac.update(auth_received.as_ref());
    let ingress_aes = Aes256::new(aes_secret.as_ref().into(),iv.as_ref().into());

    let hello_msg = gen_msg_bytes(egress_aes,egress_mac,public_key);
    stream.write(&hello_msg).await?;
    let frame = read_frame_buffer(&mut buf[bytes_used as usize..resp],ingress_aes,ingress_mac);

    Ok(())
}
pub fn convert_to_public_key(pub_key : String) -> Result<PublicKey, String> {
	let data = hex::decode(pub_key.trim()).unwrap();
    let mut s = [4_u8; 65];
    s[1..].copy_from_slice(&data);
    let public_key = match PublicKey::from_slice(&s){
    	Ok(pk) => pk,
    	Err(e) => return Err(e.to_string()),
    };
    return Ok(public_key);
}
fn gen_auth_bytes(private_key: SecretKey, remote_public_key: PublicKey,ephemeral_key: SecretKey, nonce : H256) -> BytesMut {
	
    let signature = gen_signature(private_key,remote_public_key,nonce,ephemeral_key);
    let public_key_uncomp = PublicKey::from_secret_key(SECP256K1, &private_key);
    let full_pub_key = public_key_uncomp.serialize_uncompressed();
    let public_key = &full_pub_key[1..];
    let mut stream = RlpStream::new_list(4);
    stream.append(&&signature[..]);
    stream.append(&public_key);
    stream.append(&nonce.as_bytes());
    stream.append(&ETH_PROTOCOL_VERSION);
    let auth_body = stream.out();
    let mut buf = BytesMut::default();
    let _encrypted_len = encrypt_message(auth_body, &mut buf,remote_public_key);
    buf
}
fn gen_msg_bytes(mut egress_aes : Aes256, mut egress_mac : HMac, public_key : PublicKey) -> BytesMut{
    let msg = HelloMessage {
        protocol_version: ETH_PROTOCOL_VERSION,
        client_version: "hello".to_string(),
        capabilities: vec![],
        port: 0,
        id: public_key,
    };

    let mut encoded_hello = BytesMut::default();
    encoded_hello.extend_from_slice(&rlp::encode(&0_u8));
    encoded_hello.extend_from_slice(&rlp::encode(&msg));

    let mut buf = [0; 8];
    let n_bytes = 3;
    BigEndian::write_uint(&mut buf, encoded_hello.len() as u64, n_bytes);
    let mut header_buf = [0_u8; 16];
    header_buf[..3].copy_from_slice(&buf[..3]);
    header_buf[3..6].copy_from_slice(ZERO_HEADER);
    //let egress_aes = self.egress_aes.as_mut().unwrap();
    //let egress_mac = self.egress_h_mac.as_mut().unwrap();
    egress_aes.apply_keystream(&mut header_buf);
    egress_mac.compute_header(&header_buf);
    let mac = egress_mac.digest();
    let mut out = BytesMut::default();
    out.reserve(32);
    out.extend_from_slice(&header_buf);
    out.extend_from_slice(mac.as_bytes());
    let mut len = encoded_hello.len();
    if len % 16 > 0 { len = (len / 16 + 1) * 16;}
    let old_len = out.len();
    out.resize(old_len + len, 0);
    let encrypted = &mut out[old_len..old_len + len];
    encrypted[..encoded_hello.len()].copy_from_slice(&encoded_hello);
    egress_aes.apply_keystream(encrypted);
    egress_mac.compute_frame(encrypted);
    let mac = egress_mac.digest();
    out.extend_from_slice(mac.as_bytes());
    return out;
}
fn gen_signature(private_key: SecretKey, remote_public_key: PublicKey, nonce : H256, ephemeral_key : SecretKey) -> [u8; 65] {
	
    let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
    let shared_key = H256::from_slice(
        &secp256k1::ecdh::shared_secret_point(&remote_public_key, &private_key)[..32],
    );
   
    let m = shared_key ^ nonce;
    let message = &secp256k1::Message::from_slice(m.as_bytes()).unwrap();
    let recover_sig = SECP256K1.sign_ecdsa_recoverable(message, &ephemeral_key);
    let (recipient_id, sig) = recover_sig.serialize_compact();
    let mut signature: [u8; 65] = [0; 65];
    signature[..64].copy_from_slice(&sig);
    signature[64] = recipient_id.to_i32() as u8;

    return signature;
}
fn encrypt_message(data_in: BytesMut, data_out: &mut BytesMut, remote_public_key: PublicKey) -> usize {
    let random_secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let shared_key = calculate_shared_key(&remote_public_key, &random_secret_key);
    let iv = H128::random();
    let mut key = [0_u8; 32];
    let _ = concat_kdf::derive_key_into::<sha2::Sha256>(shared_key.as_bytes(), &[], &mut key);
    let encryption_key = H128::from_slice(&key[..16]);
    let mac_key = H256::from(Sha256::digest(&key[16..32]).as_ref());
    let total_size = u16::try_from(65 + 16 + data_in.len() + 32).expect("UNEXPECTED ERROR -> This shouldn't happen.");
    let encrypted_data = encrypt_data(data_in, &iv, &encryption_key);
    let d = calculate_tag(&mac_key, &iv, &total_size.to_be_bytes(), &encrypted_data);
    prepare_output_data(data_out,&random_secret_key,&iv,&encrypted_data,&d,total_size,);
    return data_out.len();
}
fn encrypt_data(data: BytesMut, iv: &H128, encryption_key: &H128) -> BytesMut {
    let mut encryptor = Aes128::new(encryption_key.as_ref().into(), iv.as_ref().into());
    let mut encrypted_data = data;
    encryptor.apply_keystream(&mut encrypted_data);
    return encrypted_data;
}
fn calculate_shared_key(public_key: &PublicKey, private_key: &SecretKey) -> H256 {
    let shared_key_bytes = secp256k1::ecdh::shared_secret_point(public_key, private_key);
    let shared_key = H256::from_slice(&shared_key_bytes[..32]);
    return shared_key;
}
fn calculate_tag(mac_key: &H256,iv: &H128,total_size: &[u8; 2],encrypted_data: &BytesMut) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_ref()).unwrap();
    hmac.update(iv.as_bytes());
    hmac.update(encrypted_data);
    hmac.update(total_size);
    H256::from_slice(&hmac.finalize().into_bytes())
}
fn prepare_output_data(data_out: &mut BytesMut,ephemeral_key: &SecretKey,iv: &H128,encrypted_data: &[u8],tag: &H256,total_size: u16){
    data_out.extend_from_slice(&total_size.to_be_bytes());
    data_out.extend_from_slice(&PublicKey::from_secret_key(SECP256K1, ephemeral_key).serialize_uncompressed());
    data_out.extend_from_slice(iv.as_bytes());
    data_out.extend_from_slice(encrypted_data);
    data_out.extend_from_slice(tag.as_bytes());
}
fn decrypt_data<'a>(data_in: &'a mut [u8],read_bytes: &mut u16, private_key: &SecretKey) -> (&'a mut [u8],Bytes) {
    if data_in.len() < 2 { panic!("Input data too short.");}
    let payload_size = u16::from_be_bytes([data_in[0], data_in[1]]);
    *read_bytes = payload_size + 2;
    let auth_received = Bytes::copy_from_slice(&data_in[..payload_size as usize + 2]);
    if data_in.len() < payload_size as usize + 2 {panic!("Input data too short.");}
    let (_size, rest) = data_in.split_at_mut(2);
    if rest.len() < 65 {panic!("Input data too short.");}
    let (pub_data, rest) = rest.split_at_mut(65);
    let remote_emphmeral_pub_key = PublicKey::from_slice(pub_data).unwrap();
    let (iv, rest) = rest.split_at_mut(16);
    let (encrypted_data, tag) = rest.split_at_mut(payload_size as usize - (65 + 16 + 32));
    let tag = H256::from_slice(&tag[..32]);
    let shared_key = calculate_shared_key(&remote_emphmeral_pub_key, &private_key);
    let mut key = [0_u8; 32];
	let _ = concat_kdf::derive_key_into::<sha2::Sha256>(shared_key.as_bytes(), &[], &mut key);
	let encryption_key = H128::from_slice(&key[..16]);
	let mac_key = H256::from(Sha256::digest(&key[16..32]).as_ref());
    let iv = H128::from_slice(iv);
    let remote_tag = calculate_remote_tag(mac_key.as_ref(), iv, encrypted_data, payload_size);
    if tag != remote_tag {panic!("Invalid Tag Error.");}
    let encrypted_key = H128::from_slice(encryption_key.as_bytes());
    let mut decryptor = Aes128::new(encrypted_key.as_ref().into(), iv.as_ref().into());
    decryptor.apply_keystream(encrypted_data);
    return (encrypted_data,auth_received);
}
fn calculate_remote_tag(mac_key: &[u8],iv: H128,encrypted_data: &mut [u8],payload_size: u16) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC creation failed");
    hmac.update(iv.as_bytes());
    hmac.update(encrypted_data);
    hmac.update(&payload_size.to_be_bytes());
    H256::from_slice(&hmac.finalize().into_bytes())
}
fn create_hash(inputs: &[&[u8]]) -> H256 {
    let mut hasher = Keccak256::new();
    for input in inputs {
        hasher.update(input)
    }
    H256::from(hasher.finalize().as_ref())
}
fn read_frame_buffer(buf: &mut [u8],mut ingress_aes : Aes256,mut ingress_h_mac : HMac) -> Vec<u8> {
    let (header_bytes, frame) = buf.split_at_mut(32);
    let (header, mac) = header_bytes.split_at_mut(16);
    let mac = H128::from_slice(mac);
    ingress_h_mac.compute_header(header);
    if mac != ingress_h_mac.digest() {
        //return Err(Error::InvalidMac(mac));
    }

    ingress_aes.apply_keystream(header);

    let mut frame_size = BigEndian::read_uint(header, 3) + 16;
    let padding = frame_size % 16;
    if padding > 0 {
        frame_size += 16 - padding;
    }
    let (frame, _) = frame.split_at_mut(frame_size as usize);
    let (frame_data, frame_mac) = frame.split_at_mut(frame.len() - 16);
    let frame_mac = H128::from_slice(frame_mac);
    ingress_h_mac.compute_frame(frame_data);

    if frame_mac == ingress_h_mac.digest() {
        println!("\nHandshake success!\nMAC IS VALID");
        println!("Frame Mac: {:?}", frame_mac);
        println!("Ingress Mac: {:?}", ingress_h_mac.digest());
    } else {
        //return Err(Error::InvalidMac(frame_mac));
    }
    ingress_aes.apply_keystream(frame_data);
    frame_data.to_owned()
}


//Structs + Implementations for neccessary object logic
#[derive(Debug)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: PublicKey,
}
#[derive(Debug)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

//Implement RLP ENCODING and DECODING for the ethereum message types
impl Encodable for HelloMessage {
    fn rlp_append(&self, stream: &mut RlpStream) {
        let node_id = &self.id.serialize_uncompressed()[1..65];
        stream.begin_list(5);
        stream.append(&self.protocol_version);
        stream.append(&self.client_version);
        stream.append_list(&self.capabilities);
        stream.append(&self.port);
        stream.append(&node_id);
    }
}
impl Decodable for HelloMessage {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        let protocol_version: usize = rlp.val_at(0)?;
        let client_version: String = rlp.val_at(1)?;
        let capabilities: Vec<Capability> = rlp.list_at(2)?;
        let port: u16 = rlp.val_at(3)?;
        let id: Vec<u8> = rlp.val_at(4)?;
        let mut slice = [0_u8; 65];
        slice[0] = 4;
        slice[1..].copy_from_slice(&id);
        let id = PublicKey::from_slice(&slice).unwrap();

        Ok(Self {
            protocol_version,
            client_version,
            capabilities,
            port,
            id,
        })
    }
}
impl Encodable for Capability {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(2);
        stream.append(&self.name);
        stream.append(&self.version);
    }
}
impl Decodable for Capability {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let name: String = rlp.val_at(0)?;
        let version: usize = rlp.val_at(1)?;
        Ok(Self { name, version })
    }
}