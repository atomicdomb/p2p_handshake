//Protocol Constants
pub const MAGIC_BYTES: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
pub const PROTOCOL_VERSION: i32 = 70016;
pub const VERSION_COMMAND: [u8; 12] = [118, 101, 114, 115, 105, 111, 110, 0, 0, 0, 0, 0];
pub const VERACK_COMMAND: [u8; 12] = [118, 101, 114, 97, 99, 107, 0, 0, 0, 0, 0, 0];
pub const SENDCMPCT_COMMAND : [u8; 12] = [115, 101, 110, 100, 99, 109, 112, 99, 116, 0, 0, 0];

//Imports
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::time::UNIX_EPOCH;
use crate::io::Error;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::BitAnd;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use crate::endian_helpers::*;

//Primary Functions - The actual handshake logic
pub async fn perform_btc_handshake(mut stream: TcpStream) {
    let _ = perform_version_check(&mut stream).await;
    let _ = perform_verack_check(&mut stream).await; //Most modern nodes skip this step nowadays
    println!("Handshake complete.");
}
async fn perform_version_check(stream: &mut TcpStream) -> Result<(),std::io::Error> {
    //first perform the version exchange
    let version = Version::new(PROTOCOL_VERSION,SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8333),);
    let checksum = calc_checksum(&version.to_rawmessage().expect("Error"));
    let check_u32 = u32::from_le_bytes(checksum);
    let magic_num = u32::from_le_bytes(MAGIC_BYTES);
    let message = Message::new(
        magic_num,
        VERSION_COMMAND,
        check_u32,
        version.to_rawmessage().expect("oof"),
    );
    // Send version message.
    stream.write_all(&message.to_bytes()).await?;

    //Read the recieved bytes
    let mut reader = BufReader::new(stream);
    let received_bytes = match reader.fill_buf().await {
        Ok(r) => r,
        Err(_e) => panic!("Unable to fill byte buffer"),
    };
    let received_n = received_bytes.len();

    //Create a message object from the bytes
    let received_version = match Message::from_bytes(received_bytes) {
        Ok(r) => r,
        Err(e) => panic!("error matching message:{:?}", e),
    };

    //Create a version object from the message payload
    let version_message = match Version::from_rawmessage(&received_version.payload) {
        Ok(v) => v,
        Err(_e) => panic!("Failed to extract version from raw message"),
    };
    if version.nonce == version_message.nonce { panic!("Nonce conflict"); }

    //In principle the handshake is complete, originally verack messages were sent but most nodes go straight to sendcmpt.
    println!("Message Recieved:");
    println!("Version: {:?}", version_message.protocol_version);
    println!("Services: {:?}", version_message.service);
    println!("Timestamp received: {:?}", version_message.timestamp);
    
    reader.consume(received_n);
    Ok(())
}
async fn perform_verack_check(stream: &mut TcpStream) -> Result<i32,std::io::Error> {
    let check_verack = calc_checksum(&Vec::new());
    let check_verack_u32 = u32::from_le_bytes(check_verack);
    let magic_num = u32::from_le_bytes(MAGIC_BYTES);
    let verack_message = Message::new(magic_num, VERACK_COMMAND, check_verack_u32, Vec::new());
    let verack_sent = Message::to_bytes(&verack_message);
    stream.write_all(&verack_sent).await?;
    let mut reader = BufReader::new(stream);
    let received_bytes = reader.fill_buf().await?;
    let _received_n2 = received_bytes.len();
    let v_deserialised = Message::from_bytes(received_bytes)?;
    let resp = parse_btc_response(v_deserialised.get_command().to_vec());
    println!("Command received from node: {}", resp);
    Ok(0)
}

//Helper functions - Sub methods
pub fn parse_btc_response(r: Vec<u8>) -> String {
    if r == SENDCMPCT_COMMAND {
        return "sendcmpct request.".to_string(); //
    } else if r == VERACK_COMMAND {
        return "version acknowledged.".to_string(); //verack command
    } else {
        return "alternative node response".to_string();
    }
}
pub fn calc_checksum(data: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    let hash = hasher.finalize();

    let mut buf = [0u8; 4];
    buf.clone_from_slice(&hash[..4]);

    buf
}
pub fn generate_random_nonce() -> u64 {
    let mut rng = thread_rng();
    rng.gen::<u64>()
}
pub fn calculate_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

//Structs + Implementations for neccessary object logic
#[derive(Debug)]
pub struct Message {
    magic: u32,
    command: [u8; 12],
    length: u32,
    checksum: u32,
    pub payload: Vec<u8>,
}
impl Message {
    pub fn new(magic: u32, command: [u8; 12], checksum: u32, payload: Vec<u8>) -> Self {
        Self {
            magic,
            command,
            length: payload.len() as u32,
            checksum,
            payload,
        }
    }
    pub fn get_command(&self) -> [u8; 12] {
        self.command
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::new();
        buff.extend_from_slice(&self.magic.to_le_bytes());
        buff.extend_from_slice(&self.command);
        buff.extend_from_slice(&self.length.to_le_bytes());
        buff.extend_from_slice(&self.checksum.to_ne_bytes());
        buff.extend_from_slice(&self.payload);
        buff
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, Error> {
        let (magic, buff) = parse_frombytes_le::<u32>(&bytes.to_vec())?;
        let (cmd, buff) = read_drop_slice(&buff, 12)?;
        let command = <[u8; 12]>::try_from(cmd).unwrap();
        let (length, buff) = parse_frombytes_le::<u32>(&buff)?;
        let (checksum, payload) = parse_frombytes_le::<u32>(&buff)?;

        Ok(Message {
            magic,
            command,
            length,
            checksum,
            payload,
        })
    }
}

#[derive(Debug)]
pub struct Version {
    pub protocol_version: i32,
    pub service: u64,
    pub timestamp: i64,
    pub addr_recv: SocketAddrV4,
    pub addr_from: SocketAddrV4,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
}
impl Version {
    pub fn new(protocol_version: i32, addr_recv: SocketAddrV4) -> Self {
        let timestamp = calculate_timestamp();
        Version {
            protocol_version,
            service: 0x1,
            timestamp,
            addr_recv,
            addr_from: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080),
            nonce: generate_random_nonce(),
            user_agent: "".to_string(),
            start_height: 1,
        }
    }
    pub fn from_rawmessage(msg: &Vec<u8>) -> Result<Version, Error> {
        let (protocol_version, buff) = parse_frombytes_le::<i32>(msg)?;
        let (service, buff) = parse_frombytes_le::<u64>(&buff)?;
        let (timestamp, buff) = parse_frombytes_le::<i64>(&buff)?;
        let address = Self::netaddr_from_bytes(&mut buff.to_vec())?; //Our address
        let add_from = Self::netaddr_from_bytes(&mut buff.to_vec())?; //Usually dummy data nowadays
        let (nonce, _) = parse_frombytes_le::<u64>(&buff)?;
        Ok(Version {
            protocol_version,
            service,
            timestamp,
            addr_recv: address,
            addr_from: add_from,
            nonce,
            user_agent: "".to_string(),
            start_height: 1,
        })
    }
    pub fn to_rawmessage(&self) -> Result<Vec<u8>, Error> {
        let mut b: u64 = 0x0;
        b = b.bitand(*&0x1 as u64);
        let mut address_bytes = Self::netaddr_as_bytes(&b, &self.addr_recv);
        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&self.protocol_version.to_le_bytes());
        buffer.extend_from_slice(&b.to_le_bytes());
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());
        buffer.append(&mut address_bytes);
        buffer.extend_from_slice(&[0x0_u8; 26]); // addr_from
        buffer.extend_from_slice(&self.nonce.to_le_bytes());
        buffer.extend_from_slice(&[0]); // user agent
        buffer.extend_from_slice(&self.start_height.to_le_bytes());
        buffer.extend_from_slice(&[0]);
        Ok(buffer)
    }
    fn netaddr_as_bytes(node_bitmask: &u64, address: &SocketAddrV4) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&node_bitmask.to_le_bytes());
        let ip_addr_bytes = address.ip().to_ipv6_compatible().octets();
        buffer.extend_from_slice(&ip_addr_bytes);
        buffer.extend_from_slice(&address.port().to_be_bytes());
        buffer
    }
    fn netaddr_from_bytes(buff: &mut Vec<u8>) -> Result<SocketAddrV4, Error> {
        let (_, buff) = parse_frombytes_le::<u64>(&buff)?; // node service field
        let (ip_addr, buff) = read_drop_slice(&buff, 16)?;
        let (port_addr, _) = parse_frombytes_be::<u16>(&buff)?;
        let aip = &ip_addr[ip_addr.len()-4..];
        let array_ip = match <[u8;4]>::try_from(aip){
        	Ok(aip) => aip,
        	Err(e) => panic!("{:?}",e),
        };
        Ok(SocketAddrV4::new(Ipv4Addr::from(array_ip), port_addr))
    }
}