# P2P Node Handshake Example

This project is a simple command line tool that will perform a p2p handshake with either an Ethereum or Bitcoin full node. The nodes which are being connected to can be found in their respective config files in the "chain_config" directory.

## Requirements
- Rust Programming Language

## Usage

1. **Clone the Repo**
   ```bash
   git clone https://github.com/atomicdomb/p2p_handshake.git
   ```

2. **Run the Project**
   ```bash
   cargo run
   ```

3. **Interacting with the CLI**
	1. The CLI will prompt you to enter either bitcoin (b) or ethereum (e) to connect the respective nodes.
	2. If you want to connect to another node you can edit the bitcoin.config file for btc and the ethereum.config file for eth.
	3. Simply type quit or q to terminate the program.
	
4. **Config file formats**
	1. For Bitcoin the config file contains IP address followed by port:
	
		146.168.100.58:8333

	Here are some other nodes that can be conncted to:

		146.168.100.58:8333
		112.80.81.2:8333
		95.216.76.233:8333

	2. For Ethereum nodes the node public key is also required. The config file is space seperated with this format <NodeIP> <NodePubKey>:
	
		173.249.14.119:30303 000fc80db86b189ae97618c5d45e785a1c23333d73488635fc6057ee18436adbad789bb7f032eb675e50bf6b9dffb6e3aa22688d70bc84aa422bb26062feb4e1a5

	Here are some other nodes that can be conncted to:

		185.163.116.77:30305 0085d28efd4add90f67ee0641cca2c861a7bc75c8f6f03f85c72057c5fa564d7768ca54338d428ff2f4f57f77be7c0c657be9e560c7fca40e4c99dd6612b64150f
		173.249.14.119:30303 000fc80db86b189ae97618c5d45e785a1c23333d73488635fc6057ee18436adbad789bb7f032eb675e50bf6b9dffb6e3aa22688d70bc84aa422bb26062feb4e1a5
		101.100.184.228:30303 00df9e3c8a998068f8025e60858ba39f3a4fa1c4d33d3028fd847ab9e72a8f44ccc988af35c1ec23fbf1b72279531a2eb0aeee1bb2a3765e5d86cba87ebbc4cc30