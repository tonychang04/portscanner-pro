# 🤖 PortScanner Pro - AI-Powered Network Discovery Tool

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--purple.svg)](https://openai.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An intelligent network scanning tool that combines traditional port scanning with **AI-powered security analysis**. Built for hackathons, network administrators, and security enthusiasts who want to understand their network without needing advanced networking knowledge.

## ✨ Features

- 🔍 **Network Discovery** - Automatically discovers all devices on your network
- 🚪 **Port Scanning** - Scans 30+ common ports for running services
- 🤖 **AI Security Analysis** - Uses OpenAI GPT to analyze risky devices
- 📊 **Risk Assessment** - Color-coded security levels (Safe, Low, Medium, High)
- 💬 **Plain English Explanations** - Every service explained for non-technical users
- 🎯 **Smart Resource Usage** - Only runs AI analysis on Medium/High risk devices
- 🌐 **Beautiful Web UI** - Real-time results with live updates
- 📚 **Educational** - Learn about networking, ports, and security

## 🎸 Demo

![PortScanner Pro Demo](docs/demo.png)

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API Key (optional - falls back to rule-based analysis)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/portscanner-pro.git
cd portscanner-pro

# Install dependencies
pip install -r requirements.txt

# Set your OpenAI API key (optional but recommended)
echo "OPENAI_API_KEY=your_api_key_here" > .env
```

### Running

```bash
python3 app.py
```

Then open your browser to: **http://localhost:5000**

## 📖 How It Works

### Scan Process

```
1. Ping Sweep (0-50%)
   └─> Finds all live devices on the network

2. Port Scan (50-90%)
   └─> Checks common ports on each device
   └─> Identifies services and security risks

3. AI Analysis (90-100%)
   └─> Only analyzes Medium/High risk devices
   └─> Provides security insights and recommendations
```

### AI Analysis

For each risky device, the AI provides:

- **Summary** - One-sentence security overview
- **Risk Assessment** - Detailed explanation of risks
- **Attack Scenarios** - How attackers could exploit vulnerabilities
- **Recommendations** - Actionable steps to improve security
- **Priority** - HIGH/MEDIUM/LOW urgency

## 🛡️ Security Features

### Risk Levels

| Level | Color | Description |
|-------|-------|-------------|
| 🟢 Safe | Green | Normal services, no concerns |
| 🔵 Low | Blue | Common services, keep updated |
| 🟠 Medium | Orange | Requires attention, be aware |
| 🔴 High | Red | Potential security issues, act now |

### Service Database

Includes vulnerability information for:
- SSH, Telnet, FTP, RDP, VNC
- SMB, NetBIOS, Windows RPC
- MySQL, PostgreSQL, MongoDB, Redis
- And 15+ more services

## 📁 Project Structure

```
portscanner-pro/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (not in git)
├── .gitignore            # Git ignore file
├── README.md             # This file
├── templates/
│   └── index.html        # Web UI with live updates
├── static/               # Static assets (CSS, JS)
└── docs/                 # Documentation
```

## 🔧 Configuration

### Environment Variables

```bash
# .env file
OPENAI_API_KEY=sk-proj-...
```

### Scan Settings

In `app.py`, you can customize:

```python
# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, ...]

# Network range (default: /24)
NETWORK_RANGE = "192.168.1"

# Timeout for port scanning
PORT_TIMEOUT = 1  # seconds
```

## 🎯 Use Cases

- **Home Users** - See what's on your WiFi network
- **Small Businesses** - Basic network inventory
- **Students** - Learn about networking and security
- **IT Professionals** - Quick network assessment
- **Hackathons** - Demo-ready in 3 hours

## ⚠️ Important Notes

### Deployment Context

This tool scans the network it's running on:

- **On cloud server** → Scans cloud provider's network
- **On home computer** → Scans your home network
- **On office computer** → Scans office network

To scan your home network, run the tool on a device connected to your home WiFi.

### Limitations

- Can only scan the local network (not remote networks)
- Requires network access to target devices
- OpenAI API has usage limits
- Not a replacement for professional security tools

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - feel free to use this project for any purpose.

## 🙏 Acknowledgments

- Flask web framework
- OpenAI GPT for AI analysis
- All contributors and users

## 📧 Contact

For questions or feedback, please open an issue on GitHub.

---

**Built with ❤️ for [Hackathon Name]**
