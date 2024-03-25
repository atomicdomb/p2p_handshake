//Imports
use std::io;
use tokio::net::TcpStream;

//Custom crates
use crate::bitcoin_handshake::*;
use crate::ethereum_handshake::*;

mod bitcoin_handshake;
mod ethereum_handshake;
mod endian_helpers;

//This is essentially a CLI driver to perform handshakes to various blockchains
#[tokio::main(flavor = "current_thread")]
async fn main() {

    println!("This is a blockchain node p2p handshake demonstration.");
    println!("==========================================================================");
    println!("Choose between Bitcoin (b), Ethereum (e), Polygon (p), Solana (s),\nhelp (h) or quit (q).");

    loop{
        println!("\nSelect a blockchain to perform a p2p handshake with, or quit (q):\n");
        let mut command = String::new();
        io::stdin().read_line(&mut command).expect("Failed to read line");

        if command.trim() == "bitcoin" || command.trim() == "b"{
            println!("\nBitcoin blockchain - Node IP 178.162.165.203:8333");
            match handle_connection("178.162.165.203:8333").await {
                Ok(s) => perform_btc_handshake(s).await,
                Err(e) => println!("{:?}",e.to_string()),
            };
        }else if command.trim() == "ethereum" || command.trim() == "e"{
            println!("\nEthereum blockchain - Node IP 23.92.70.178:30304");
            let pub_key = convert_to_public_key("000314fd109a892573fe8ca8adfd2ed2a5259b3ca98a9b5a2e7f6fa495b5f258565861bf378cb4c2f250a06d9aa008d770c9c87a7364ae25fb3f29fa92af375f".to_string()).unwrap();
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