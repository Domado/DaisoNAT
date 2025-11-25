# DaisoNAT  
💻 Advanced, high-speed, lightweight, open-source NAT penetration tool, made by Daiso

DaisoNAT is a cross-platform, high-performance NAT traversal and penetration tool designed to provide stable, low-latency peer-to-peer communication in complex network environments. It focuses on speed, reliability, low resource usage, and developer-friendly integration.

## ✨ Features
- 🚀 **High Performance**: Optimized UDP/TCP channels with an efficient event-driven architecture  
- 🔧 **Multiple Modes**: Supports P2P, port mapping, relay mode, and more  
- 🔒 **Secure**: Optional encrypted tunnels with multi-level authentication  
- 🌐 **Cross-Platform**: Fully supports Windows, macOS, and Linux  
- 🧩 **Developer Friendly**: Clean, easy-to-integrate API design  
- 🪶 **Lightweight**: Minimal dependencies and extremely low resource usage

## 📦 Installation
```bash
git clone https://github.com/daisoai/DaisoNAT.git
cd DaisoNAT
make
```

Or download prebuilt binaries from the Releases page.

## 🚦 Quick Start
```bash
# Start the server
daisonat.py server --port 7000

# Connect a client
daisonat.py client --server <server-ip>:7000 --target 8080
```

## 📚 Use Cases
- Remote desktop / SSH access to devices behind NAT  
- Exposing local web services to the internet  
- Enhancing connectivity for multiplayer or P2P applications  
- Remote monitoring and IoT device connectivity  

## 🛠️ Roadmap
- [ ] Automatic STUN/TURN negotiation  
- [ ] DCP support  
- [ ] Web-based management UI  
- [ ] Plugin extension system  

## 🤝 Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.

## 📄 License
This project is released under the MIT License.
