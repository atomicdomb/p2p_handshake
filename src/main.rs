use std::io;
use tokio::net::TcpStream;

use crate::bitcoin_handshake::*;

mod bitcoin_handshake;
mod endian_helpers;

//This is essentially a CLI driver to perform handshakes to various blockchains
#[tokio::main(flavor = "current_thread")]
async fn main() {

    println!("This is a blockchain node p2p handshake demonstration.");
    println!("==========================================================================");
    println!("Choose between Bitcoin (b), Ethereum (e), Polygon (p), Solana (s),\nhelp (h) or quit (q).");

    loop{
        println!("Select a blockchain to perform a p2p handshake with, or quit (q):\n");
        let mut command = String::new();
        io::stdin().read_line(&mut command).expect("Failed to read line");

        if command.trim() == "bitcoin" || command.trim() == "b"{
            println!("\nBitcoin blockchain - Node IP 178.162.165.203:8333");
            match handle_connection("178.162.165.203:8333").await {
                Ok(s) => perform_btc_handshake(s).await,
                Err(e) => println!("{:?}",e.to_string()),
            };
        }else if command.trim() == "ethereum" || command.trim() == "e"{
            println!("\nEthereum blockchain - ");
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