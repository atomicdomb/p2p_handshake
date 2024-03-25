//Protocol Constants
pub const ZERO_HEADER: &[u8; 3] = &[194, 128, 128];
pub const ETH_PROTOCOL_VERSION: usize = 5;

//Imports
use std::ops::BitAnd;
use bytes::{Bytes, BytesMut};
use ethereum_types::{H128, H256};
use std::net::{Ipv4Addr, SocketAddrV4};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use rlp::{Rlp, RlpStream};
use aes::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use concat_kdf::Error;
use hmac::{Hmac, Mac as h_mac};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

pub type AES = ctr::Ctr64BE<aes::Aes128>;

pub async fn perform_eth_handshake(mut stream: TcpStream, node_public_key: PublicKey) -> Result<(),std::io::Error> {
    println!("starting handshake...");
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    //let mut handshake = HandShake::new(private_key, node_public_key);

    let auth_encrypted = gen_auth_bytes(private_key,node_public_key);
    stream.write(&auth_encrypted).await?;
    println!("Auth message send to target node");
    let mut buf = [0_u8; 1024];
    let resp = stream.read(&mut buf).await?;
    let mut bytes_used = 0u16;
    let decrypted = decrypt_data(&mut buf, &mut bytes_used, &private_key);
    println!("Hello Response from Node:{:?}", decrypted);

    //handshake.derive_secrets(decrypted)?;

    //let hello_frame = handshake.hello_message();
    //stream.write(&hello_frame).await?;

    //let frame = handshake.read_frame(&mut buf[bytes_used as usize..resp])?;
    //decode_hello_message(frame)?;
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
fn gen_auth_bytes(private_key: SecretKey, remote_public_key: PublicKey) -> BytesMut {
	let nonce = H256::random();
    let signature = gen_signature(private_key,remote_public_key,nonce);
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

fn gen_signature(private_key: SecretKey, remote_public_key: PublicKey, nonce : H256) -> [u8; 65] {
	let ephemeral_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
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
    let mut encryptor = AES::new(encryption_key.as_ref().into(), iv.as_ref().into());
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
fn decrypt_data<'a>(data_in: &'a mut [u8],read_bytes: &mut u16, private_key: &SecretKey) -> &'a mut [u8] {
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
        let mut decryptor = AES::new(encrypted_key.as_ref().into(), iv.as_ref().into());
        decryptor.apply_keystream(encrypted_data);
        return encrypted_data;
}
fn calculate_remote_tag(mac_key: &[u8],iv: H128,encrypted_data: &mut [u8],payload_size: u16) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC creation failed");
    hmac.update(iv.as_bytes());
    hmac.update(encrypted_data);
    hmac.update(&payload_size.to_be_bytes());
    H256::from_slice(&hmac.finalize().into_bytes())
}