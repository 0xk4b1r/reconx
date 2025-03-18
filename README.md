# reconX - Comprehensive Reconnaissance Framework

<p align="center">
  <img src="https://raw.githubusercontent.com/0xk4b1r/reconx/main/logo.png" alt="reconX Logo" width="300px">
  <br>
  <i>A modular reconnaissance framework for efficient and comprehensive target scanning</i>
  <br>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#modules">Modules</a> •
  <a href="#workflows">Workflows</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

## Overview

**reconX** is an advanced reconnaissance framework designed to streamline the process of discovering and analyzing target infrastructure. Built with security professionals, bug bounty hunters, and penetration testers in mind, reconX integrates and orchestrates multiple popular open-source tools into a cohesive, efficient workflow.

> ⚠️ **Disclaimer**: This tool is for educational purposes and legal security testing only. Always obtain proper authorization before performing security testing on any system you do not own.

## Features

- 🔍 **Comprehensive Discovery**: Find subdomains, open ports, endpoints, JavaScript files, and more
- 🧩 **Modular Design**: Run individual modules or full scans based on your needs
- 🚀 **Parallel Processing**: Multi-threaded operations for faster scanning
- 📊 **Detailed Reporting**: Organized output with summaries and statistics  
- 🔧 **Extensible Architecture**: Easy to add new tools and modules
- 📝 **Well-Documented Code**: Clear documentation for each module and function
- 🔄 **Intelligent Workflows**: Smart dependency management between scanning phases

## Installation

### Quick Install

```bash
git clone https://github.com/0xk4b1r/reconx.git
cd reconx
python3 install.py
```

### Manual Installation

If you prefer to customize your installation:

```bash
git clone https://github.com/0xk4b1r/reconx.git
cd reconx
python3 install.py --verbose --directory ~/custom/tools
```

### Installation Options

```
usage: install.py [-h] [-d DIRECTORY] [-v] [--force] [--skip-system-packages] [--skip-go-tools] [--skip-python-tools] [--skip-git-tools]

reconX Installer - Install all dependencies and tools

options:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Custom directory to install tools
  -v, --verbose         Enable verbose output
  --force               Force reinstallation of existing tools

Feature Selection:
  --skip-system-packages
                        Skip installation of system packages
  --skip-go-tools       Skip installation of Go tools
  --skip-python-tools   Skip installation of Python tools
  --skip-git-tools      Skip installation of Git tools
```

### Requirements

- Python 3.7+
- Git
- Linux, macOS, or WSL (Windows Subsystem for Linux)

## Usage

### Basic Usage

```bash
python3 reconx.py -d example.com --subs
```

### Full Scan

```bash
python3 reconx.py -d example.com --full
```

### Individual Modules

```bash
# Subdomain discovery
python3 reconx.py -d example.com --subs

# Port scanning
python3 reconx.py -d example.com --ports

# URL enumeration
python3 reconx.py -d example.com --urls

# Nmap scanning
python3 reconx.py -d example.com --nmap

# Web enumeration (technologies & screenshots)
python3 reconx.py -d example.com --web

# JavaScript analysis
python3 reconx.py -d example.com --js

# Sensitive information discovery
python3 reconx.py -d example.com --sens
```

### Advanced Options

```bash
# Custom threads and timeout
python3 reconx.py -d example.com --full --threads 20 --timeout 3600

# Verbose output
python3 reconx.py -d example.com --full --verbose

# Custom output directory
python3 reconx.py -d example.com --full --output ~/recon/example.com
```

## Modules

reconX consists of the following modules:

| Module | Description | Main Tools |
|--------|-------------|------------|
| **subfinder.py** | Subdomain discovery | subfinder, assetfinder, amass |
| **port_scanner.py** | Port scanning | naabu, masscan |
| **urls_enum.py** | URL and endpoint discovery | waybackurls, gau, hakrawler |
| **nmap.py** | Service fingerprinting | nmap |
| **web_enum.py** | Web technology identification and screenshots | whatweb, aquatone, nikto |
| **js_scan.py** | JavaScript analysis and secrets discovery | subjs, custom analysis |
| **sensitive_info_enum.py** | Discover sensitive files and info | custom checks, httpx |

## Workflows

reconX can be used in various workflows:

1. **Quick Discovery**: `--subs --ports` for basic infrastructure mapping
2. **Web Application Focus**: `--subs --web --js --sens` for web app reconnaissance  
3. **Full Spectrum**: `--full` for comprehensive scanning
4. **Targeted Approach**: Run specific modules based on your objectives

## Directory Structure

```
.
├── reconx.py                # Main script
├── modules/                 # Module directory
│   ├── subfinder.py         # Subdomain enumeration
│   ├── port_scanner.py      # Port scanning
│   ├── urls_enum.py         # URL enumeration
│   ├── nmap.py              # Nmap scanning
│   ├── web_enum.py          # Web enumeration
│   ├── js_scan.py           # JavaScript scanning
│   └── sensitive_info_enum.py # Sensitive info scanning
├── install.py               # Installation script
├── config.py                # Configuration file
└── test/                    # Output directory
    └── output/              # Scan results
        └── example.com/     # Domain-specific results
```

## Output Structure

For each scanned domain, reconX creates a structured output directory:

```
test/output/example.com/
├── subdomains.txt           # Discovered subdomains
├── ports.txt                # Open ports
├── urls.txt                 # Discovered URLs
├── nmap/                    # Nmap scan results
├── screenshots/             # Website screenshots
├── js/                      # JavaScript analysis
│   ├── files/               # Downloaded JS files
│   ├── endpoints.txt        # Extracted endpoints
│   └── secrets.txt          # Potential secrets
└── sensitive/               # Sensitive information findings
```

## Contributing

Contributions to reconX are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Credits

reconX integrates and builds upon many excellent open-source tools from the security community. We're grateful to all the developers and contributors of these tools.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/0xk4b1r">@0xk4b1r</a>
</p>