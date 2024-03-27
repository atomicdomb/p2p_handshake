//Imports
use std::io;
use std::fs;
use tokio::net::TcpStream;

//Custom crates
use crate::bitcoin_handshake::*;
use crate::ethereum_handshake::*;

mod bitcoin_handshake;
mod ethereum_handshake;
mod endian_helpers;
mod hmac;

//This is essentially a CLI driver to perform handshakes to various blockchains
#[tokio::main(flavor = "current_thread")]
async fn main() {

    println!("This is a blockchain node p2p handshake demonstration.");
    println!("==========================================================================");
    println!("Choose between Bitcoin (b), Ethereum (e), help (h) or quit (q).");

    loop{
        println!("\nSelect a blockchain to perform a p2p handshake with, or quit (q):\n");
        let mut command = String::new();
        io::stdin().read_line(&mut command).expect("Failed to read line");

        if command.trim() == "bitcoin" || command.trim() == "b"{
            let ip_addr = fs::read_to_string("./src/chain_config/bitcoin.config").expect("Should have been able to read the file.");
            println!("\nBitcoin blockchain - Node IP {:?}",ip_addr);
            match handle_connection(&ip_addr).await {
                Ok(s) => perform_btc_handshake(s).await,
                Err(e) => println!("{:?}",e.to_string()),
            };
        }else if command.trim() == "ethereum" || command.trim() == "e"{
            let split_str = fs::read_to_string("./src/chain_config/ethereum.config").expect("Should have been able to read the file.");
            let parts : Vec<&str> = split_str.split(" ").collect();
            if parts.len() < 2{
               println!("Eth config file set up incorrectly. You need an IP Address and Node Public Key.");
               continue; 
            }
            println!("\nEthereum blockchain - Node IP {:?}",parts[0].trim());
            println!("Node Public Key (Hex): \n{:?}",parts[1].trim());
            let pub_key = match convert_to_public_key("000314fd109a892573fe8ca8adfd2ed2a5259b3ca98a9b5a2e7f6fa495b5f258565861bf378cb4c2f250a06d9aa008d770c9c87a7364ae25fb3f29fa92af375f".to_string()){
                Ok(pk) => pk,
                Err(_) => {println!("Invalid Public Key hex string.");continue;}
            };
            match handle_connection("23.92.70.178:30304").await {
                Ok(s) => perform_eth_handshake(s,pub_key).await.unwrap(), 
                Err(e) => println!("{:?}",e.to_string()),
            };
        }else if command.trim() == "help" || command.trim() == "h"{
            println!("\nYou can simply type the blockchain you want to connect to or the first letter.");
            println!("So for bitcoin you can type 'b'.");
        }else if command.trim() == "quit" ||  command.trim() == "q"{
            println!("\nThank you for trying out this handshake demo! Cheers!");
            break;
        }
    }
}

//Handle the TCP connection to the IP.
async fn handle_connection(sock_addr: &str) -> Result<TcpStream,String> {
    let stream = match TcpStream::connect(sock_addr).await {
        Ok(s) => s,
        Err(e) => return Err(format!("Failed to connect. {:?}",e)),
    };
    return Ok(stream);
}