Here's the updated README.md with the Docker commands added to the **Docker Installation** section and a new **Docker Management** section:

---

# clamNET - Advanced Malware Detection & Network Security Platform

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Flask](https://img.shields.io/badge/flask-2.0%2B-red)
![Docker](https://img.shields.io/badge/docker-ready-blue)

**clamNET** is a comprehensive, enterprise-grade security platform that combines multiple malware detection engines, network traffic analysis, and threat intelligence capabilities into a unified web interface. Built for security professionals, SOC analysts, and system administrators.

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Docker Management](#-docker-management)
- [Module Documentation](#-module-documentation)
- [API Reference](#-api-reference)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

## 🚀 Key Features

### 🔬 **Multi-Engine Malware Analysis**
| Engine | Capabilities | Supported Formats |
|--------|------------|-------------------|
| **ClamAV** | Signature-based detection | All files, archives |
| **YARA** | Pattern matching rules | Custom rules, IOC scanning |
| **Maldet** | Heuristic analysis | Linux executables |
| **AI/ML** | Behavioral analysis | PE, ELF, APK, Documents |

### 📡 **Network Security**
- **PCAP Analysis** - Deep packet inspection, protocol analysis, traffic patterns
- **Threat Detection** - Anomaly detection, port scanning identification, DNS tunneling
- **Visualization** - Protocol distribution, top talkers, timeline analysis

### 📱 **Mobile Security**
- **Android APK Analysis** - Permission auditing, API call extraction
- **Transformer-based ML** - NyerAndroidMalware model integration
- **Risk Scoring** - Probability-based malware classification

### 🖥️ **Remote Deployment**
- **SSH-based Installation** - Automated ClamAV deployment across Windows/Linux
- **Mass Deployment** - Multi-host parallel installation
- **Database Updates** - Remote signature database synchronization

### 🔍 **Advanced Analysis**
- **Control Flow Analysis** - Obfuscation detection, dispatcher identification
- **PE Analysis** - Section analysis, import/export tables, resource inspection
- **IOC Scanning** - Hash matching, domain/IP blacklisting

### 📊 **Comprehensive Reporting**
- JSON export capabilities
- Real-time visualization
- Threat scoring system
- Detailed forensic evidence

---

## 🏗 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Interface (Flask)                     │
├─────────────────────────────────────────────────────────────┤
│                    Authentication Layer                      │
├───────────┬───────────┬───────────┬───────────┬───────────┤
│   File    │   PCAP    │   APK     │   CFG     │  Remote   │
│  Scanner  │  Analyzer │ Analyzer  │ Analyzer  │ Deployer  │
├───────────┴───────────┴───────────┴───────────┴───────────┤
│                    Orchestration Layer                      │
├───────────┬───────────┬───────────┬───────────┬───────────┤
│  ClamAV   │   YARA    │  Maldet   │   AI/ML   │   IOC     │
│  Engine   │  Engine   │  Engine   │  Engine   │ Database  │
└───────────┴───────────┴───────────┴───────────┴───────────┘
```

---

## 💻 Installation

### Prerequisites

```bash
# System dependencies
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon yara python3-pip docker docker-compose
```

### Option 1: Docker Installation (Recommended)

```bash
# Clone repository
git clone https://github.com/KYGnus/clamNET.git
cd clamNET

# Build and run with Docker Compose
docker-compose up --build

# Or build manually
docker build -t clamnet:latest .
docker run -d \
  -p 5005:5005 \
  -v clamnet_uploads:/app/uploads \
  -v clamnet_results:/app/scan_results \
  -v clamnet_ioc:/app/ioc_rules \
  --name clamnet \
  clamnet:latest
```

### Option 2: Manual Installation

```bash
# Clone repository
git clone https://github.com/KYGnus/clamNET.git
cd clamNET

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-main.txt
pip install -r app/scripts_requirements.txt

# Configure
cp config.example.py app/config.py
# Edit app/config.py with your settings

# Initialize directories
mkdir -p uploads scan_results ioc_rules/yara
```

---

## ⚡ Quick Start

1. **Configure credentials** in `app/config.py`:
```python
SECRET_KEY = "your-secret-key-here"
USERNAME = "admin"
PASSWORD = "secure-password"
MAINDIR = "/path/to/clamNET"
```

2. **Launch the application**:
```bash
cd app
python main.py
```

3. **Access the web interface**:
```
http://localhost:5005
```

4. **Default login**:
- Username: `admin`
- Password: `[as configured]`

---

## 🐳 Docker Management

### Basic Docker Commands

```bash
# Check logs
docker logs -f clamnet

# Execute commands in container
docker exec -it clamnet bash

# Check ClamAV status
docker exec clamnet clamdscan --version
docker exec clamnet freshclam --version

# Test Maldet
docker exec clamnet maldet --help

# Stop container
docker stop clamnet

# Start container
docker start clamnet

# Remove container
docker rm clamnet

# Remove image
docker rmi clamnet:latest
```

### Docker Compose Commands

```bash
# Start services in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Rebuild and start
docker-compose up --build

# Scale services (if configured)
docker-compose up --scale clamnet=2
```

### Volume Management

```bash
# List volumes
docker volume ls | grep clamnet

# Inspect volume
docker volume inspect clamnet_uploads

# Backup volume
docker run --rm -v clamnet_uploads:/source -v $(pwd):/backup alpine tar czf /backup/clamnet_uploads_backup.tar.gz -C /source .

# Restore volume
docker run --rm -v clamnet_uploads:/target -v $(pwd):/backup alpine tar xzf /backup/clamnet_uploads_backup.tar.gz -C /target
```

### Health Checks

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' clamnet

# Monitor resource usage
docker stats clamnet

# Check running processes
docker top clamnet
```

---

## 📚 Module Documentation

### 1. **File Scanner Module**
**Location**: `app/main.py` - ComprehensiveFileScanner class

```python
# Example: Programmatic scanning
from malware_scanner import MalwareAnalyzer

analyzer = MalwareAnalyzer("/path/to/suspicious.exe")
results = analyzer.run_analysis()
print(f"Verdict: {results['verdict']}")
print(f"Score: {results['score']}")
```

**Detection Capabilities**:
- ✅ ClamAV signature matching
- ✅ YARA pattern matching
- ✅ Maldet heuristic analysis  
- ✅ Hash-based IOC detection
- ✅ File type identification
- ✅ Entropy analysis

### 2. **PCAP Analyzer Module**
**Location**: `app/main.py` - EnhancedPCAPAnalyzer class

**Analysis Features**:
- 📦 Protocol distribution (TCP/UDP/ICMP/HTTP/DNS)
- 📊 Top talker identification
- 🔍 Anomaly detection
- 🚨 Security indicator analysis
- 📈 Traffic pattern analysis
- 🎨 Visualizations (matplotlib)

**Output Example**:
```json
{
  "basic_stats": {
    "total_packets": 15234,
    "duration_seconds": 120.5,
    "packet_rate": 126.4
  },
  "security_indicators": {
    "suspicious_ips": ["192.168.1.100"],
    "dns_tunneling": []
  }
}
```

### 3. **Android APK Analyzer**
**Location**: `app/main.py` - HuggingFace transformer integration

**Model**: `Hachirou18/NyerAndroidMalware`
**Accuracy**: ~94% on test datasets

**Features Extracted**:
- 📱 Permissions (dangerous/normal)
- 📱 API calls
- 📱 Intent filters
- 📱 Activities & Services

### 4. **Remote Deployment Module**
**Location**: `app/main.py` - ClamAVInstaller class

**Supported Platforms**:
| OS | Distribution | Architecture |
|----|-------------|--------------|
| Linux | Ubuntu 18.04+ | x86_64, ARM |
| Linux | Debian 10+ | x86_64, ARM |
| Linux | CentOS 7+ | x86_64 |
| Linux | Fedora 32+ | x86_64 |
| Windows | Windows 10/11 | x86_64 |
| Windows | Windows Server 2016+ | x86_64 |

### 5. **Control Flow Analysis**
**Location**: `app/main.py` - EnhancedCFGAnalyzer class

**Techniques Detected**:
- 🔄 Opaque predicates
- 🎯 Dispatcher-based obfuscation
- 📍 Control flow flattening
- 🔀 Dead code insertion

---

## 🔌 API Reference

### REST Endpoints

| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| POST | `/login` | User authentication | ❌ No |
| GET | `/` | Dashboard | ✅ Yes |
| POST | `/upload-scan-file` | Upload file for scanning | ✅ Yes |
| POST | `/upload-pcap-file` | PCAP analysis | ✅ Yes |
| POST | `/upload-malware-file` | Malware analysis | ✅ Yes |
| POST | `/upload-pepper-file` | Pepper analysis | ✅ Yes |
| GET | `/download-scan-result` | Download JSON results | ✅ Yes |

### WebSocket Events (SSE)

| Endpoint | Purpose | Event Types |
|----------|---------|-------------|
| `/perform-ioc-scan` | IOC scanning | `data: PROGRESS:X`, `data: COMPLETED` |
| `/update-databases` | Remote updates | `data: ✅ HOST: Success` |
| `/perform-pepper-analysis` | Pepper execution | `data: raw output` |

---

## 📁 Project Structure

```
clamNET/
├── app/                          # Application core
│   ├── main.py                  # Main Flask application
│   ├── config.py                # Configuration settings
│   ├── malware_scanner.py       # Malware analysis engine
│   ├── pepper.py                # Pepper framework integration
│   ├── capa/                    # CAPA rules directory
│   ├── floss/                   # FLOSS strings extraction
│   ├── modules/                 # Additional modules
│   │   └── pcap.py             # PCAP processing utilities
│   ├── static/                  # Static assets
│   │   ├── css/                # Stylesheets
│   │   ├── js/                 # JavaScript
│   │   └── img/                # Images
│   ├── templates/               # Jinja2 templates
│   │   ├── main.html           # Dashboard
│   │   ├── file_scan.html      # File scanner UI
│   │   ├── pcap_scan.html      # PCAP analyzer UI
│   │   ├── android_analysis.html # APK analyzer
│   │   ├── malware_analysis.html # Malware scanner
│   │   ├── pepper_analysis.html # Pepper interface
│   │   ├── cfg_results.html    # CFG analysis results
│   │   ├── login.html          # Authentication
│   │   └── about.html          # About page
│   └── signatures/              # Detection signatures
│
├── ioc_rules/                   # Threat intelligence
│   ├── ioc_database.json       # Hash/domain/IP database
│   ├── yara/                   # YARA rules directory
│   └── malware_yara_rules.py   # Rule management
│
├── uploads/                     # File upload directory
├── scan_results/               # Analysis results storage
├── Dockerfile                  # Container configuration
├── docker-compose.yml          # Docker Compose configuration
├── requirements.txt            # Python dependencies
├── requirements-main.txt       # Core dependencies
├── tools.txt                  # Third-party tools manifest
└── README.md                  # This documentation
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Flask session secret | - | ✅ Yes |
| `USERNAME` | Admin username | - | ✅ Yes |
| `PASSWORD` | Admin password | - | ✅ Yes |
| `MAINDIR` | Application directory | - | ✅ Yes |
| `UPLOADDIR` | Upload directory | `./uploads` | ❌ No |
| `SCAN_RESULTS` | Results directory | `./scan_results` | ❌ No |

### config.py Example

```python
# Authentication
SECRET_KEY = "your-strong-secret-key-here"
USERNAME = "admin"
PASSWORD = "your-secure-password"

# Directories
MAINDIR = "/opt/clamNET"
UPLOADDIR = os.path.join(MAINDIR, "uploads")
SCAN_RESULTS = os.path.join(MAINDIR, "scan_results")
IOC_RULES = os.path.join(MAINDIR, "ioc_rules")
YARA_RULES = os.path.join(IOC_RULES, "yara")

# Remote installation files
LOCAL_INSTALL_FILE = os.path.join(MAINDIR, "installers/clamav-1.2.0-win64.msi")
LOCAL_CVD_FILE = os.path.join(MAINDIR, "databases/daily.cvd")
```

---

## 🧪 Testing

```bash
# Run unit tests
python -m pytest tests/

# Test specific module
python -m pytest tests/test_file_scanner.py

# Load testing
python -m locust -f tests/locustfile.py

# Test Docker container
docker exec clamnet python -m pytest tests/
```

---

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

**Contribution Guidelines:**
- Follow PEP 8 style guide
- Add unit tests for new features
- Update documentation
- Ensure all tests pass
- Test Docker builds locally

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 KYGnus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
```

---

## 📞 Contact & Support

**Developer:** KYGnus

📧 **Email:** kygnus.co@proton.me

🐙 **GitHub:** [https://github.com/KYGnus](https://github.com/KYGnus)

🌐 **Website:** [https://kygnus.github.io](https://kygnus.github.io)


---

## 🙏 Acknowledgments

- **ClamAV** - Open source antivirus engine
- **YARA** - Pattern matching tool
- **Androguard** - Android APK analysis
- **HuggingFace** - Transformer models
- **LIEF** - Binary parsing
- **Capstone** - Disassembly framework
- **Scapy/Pyshark** - Network analysis
- **Docker** - Containerization platform

---

## 🗺️ Roadmap

- [ ] Integration with VirusTotal API
- [ ] check Malicious URL with AI
- [ ] analyze .exe Files with AI
- [ ] Log Files Analyzer
- [ ] Docker Swarm support



---

**Made with 🔥 by KYGnus**

*Protecting digital assets, one scan at a time.*