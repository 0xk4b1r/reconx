#!/usr/bin/env python3
"""
install.py - Installation script for reconX

This script installs all dependencies and tools required by the reconX framework.
It supports different operating systems and package managers, and provides
detailed feedback during the installation process.

Author: @0xk4b1r
License: MIT
"""

import os
import sys
import subprocess
import platform
import shutil
import logging
from pathlib import Path
import argparse
import time
import json
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
import tempfile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('install')


class SystemManager:
    """Class for managing system dependencies and tool installations."""

    def __init__(self, tools_dir: Optional[Path] = None,
                 verbose: bool = False,
                 force_install: bool = False,
                 skip_system_packages: bool = False,
                 skip_go_tools: bool = False,
                 skip_python_tools: bool = False,
                 skip_git_tools: bool = False,
                 install_all: bool = True):
        """
        Initialize the system manager.

        Args:
            tools_dir: Directory to install tools (default: ~/tools)
            verbose: Whether to enable verbose output
            force_install: Whether to force reinstallation of tools
            skip_system_packages: Whether to skip system package installation
            skip_go_tools: Whether to skip Go tool installation
            skip_python_tools: Whether to skip Python tool installation
            skip_git_tools: Whether to skip Git tool installation
            install_all: Whether to install all tools
        """
        self.tools_dir = tools_dir or Path.home() / "tools"
        self.verbose = verbose
        self.force_install = force_install
        self.skip_system_packages = skip_system_packages
        self.skip_go_tools = skip_go_tools
        self.skip_python_tools = skip_python_tools
        self.skip_git_tools = skip_git_tools
        self.install_all = install_all

        # Set up environment
        self.os_type = self._detect_os()
        self.package_manager = self._detect_package_manager()

        # Create installation logs directory
        self.logs_dir = Path.home() / ".reconx" / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        # Set log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.logs_dir / f"install_{timestamp}.log"

        # Add file handler to logger
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        logger.addHandler(file_handler)

        # Set logging level based on verbosity
        if verbose:
            logger.setLevel(logging.DEBUG)
            for handler in logger.handlers:
                handler.setLevel(logging.DEBUG)

        # Installation status tracking
        self.installed_tools = {
            'system_packages': [],
            'go_tools': [],
            'python_tools': [],
            'git_tools': [],
            'other_tools': []
        }

        self.failed_tools = {
            'system_packages': [],
            'go_tools': [],
            'python_tools': [],
            'git_tools': [],
            'other_tools': []
        }

    def _detect_os(self) -> str:
        """
        Detect the operating system.

        Returns:
            str: Operating system type (linux, darwin, windows)
        """
        system = platform.system().lower()

        if system == 'linux':
            # Check for specific distributions
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release = f.read()
                    if 'kali' in os_release.lower():
                        return 'kali'
                    elif 'ubuntu' in os_release.lower():
                        return 'ubuntu'
                    elif 'debian' in os_release.lower():
                        return 'debian'
                    elif 'centos' in os_release.lower() or 'redhat' in os_release.lower():
                        return 'centos'
                    elif 'fedora' in os_release.lower():
                        return 'fedora'
                    elif 'arch' in os_release.lower():
                        return 'arch'
            except Exception:
                pass
            return 'linux'
        elif system == 'darwin':
            return 'darwin'
        elif system == 'windows':
            return 'windows'
        else:
            logger.warning(f"Unknown operating system: {system}")
            return system

    def _detect_package_manager(self) -> str:
        """
        Detect the system package manager.

        Returns:
            str: Package manager (apt, yum, dnf, pacman, brew, choco)
        """
        if self.os_type in ['ubuntu', 'debian', 'kali']:
            return 'apt'
        elif self.os_type == 'centos':
            # Check if dnf is available
            if shutil.which('dnf'):
                return 'dnf'
            else:
                return 'yum'
        elif self.os_type == 'fedora':
            return 'dnf'
        elif self.os_type == 'arch':
            return 'pacman'
        elif self.os_type == 'darwin':
            # Check if brew is installed
            if shutil.which('brew'):
                return 'brew'
            else:
                logger.warning("Homebrew not found. Please install Homebrew first: https://brew.sh/")
                return 'none'
        elif self.os_type == 'windows':
            # Check if chocolatey is installed
            if shutil.which('choco'):
                return 'choco'
            else:
                logger.warning("Chocolatey not found. Please install Chocolatey first: https://chocolatey.org/")
                return 'none'
        else:
            logger.warning("Could not detect package manager")
            return 'none'

    def run_command(self, command: Union[str, List[str]], check: bool = True,
                    shell: bool = True, timeout: Optional[int] = None,
                    cwd: Optional[str] = None) -> Tuple[bool, str, str]:
        """
        Run a shell command.

        Args:
            command: The command to run (string or list of arguments)
            check: Whether to check for command success
            shell: Whether to run the command in a shell
            timeout: Timeout in seconds
            cwd: Working directory

        Returns:
            Tuple[bool, str, str]: Success flag, stdout, stderr
        """
        if isinstance(command, list):
            cmd_str = ' '.join(command)
        else:
            cmd_str = command

        logger.debug(f"Running: {cmd_str}")

        try:
            process = subprocess.run(
                command,
                check=check,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                cwd=cwd
            )
            return True, process.stdout, process.stderr
        except subprocess.CalledProcessError as e:
            logger.debug(f"Command failed: {cmd_str}")
            logger.debug(f"Error: {e}")
            logger.debug(f"stdout: {e.stdout}")
            logger.debug(f"stderr: {e.stderr}")
            return False, e.stdout if e.stdout else "", e.stderr if e.stderr else ""
        except subprocess.TimeoutExpired as e:
            logger.debug(f"Command timed out: {cmd_str}")
            return False, "", f"Timeout after {timeout} seconds"
        except Exception as e:
            logger.debug(f"Error running command: {cmd_str}")
            logger.debug(f"Exception: {e}")
            return False, "", str(e)

    def create_tool_directories(self) -> None:
        """Create the necessary directories for tools."""
        logger.info("Creating tool directories...")

        # Create main tools directory
        self.tools_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (self.tools_dir / "bin").mkdir(exist_ok=True)
        (self.tools_dir / "go").mkdir(exist_ok=True)
        (self.tools_dir / "python").mkdir(exist_ok=True)
        (self.tools_dir / "git").mkdir(exist_ok=True)

        logger.info(f"Created directory structure at {self.tools_dir}")

    def update_system(self) -> bool:
        """
        Update system package repositories.

        Returns:
            bool: True if successful, False otherwise
        """
        if self.skip_system_packages:
            logger.info("Skipping system update (--skip-system-packages)")
            return True

        logger.info("Updating system package repositories...")

        if self.package_manager == 'apt':
            success, stdout, stderr = self.run_command("apt-get -y update")
            return success
        elif self.package_manager in ['yum', 'dnf']:
            success, stdout, stderr = self.run_command(f"{self.package_manager} -y check-update", check=False)
            # yum/dnf check-update returns 100 if updates are available
            return True
        elif self.package_manager == 'pacman':
            success, stdout, stderr = self.run_command("pacman -Sy")
            return success
        elif self.package_manager == 'brew':
            success, stdout, stderr = self.run_command("brew update")
            return success
        elif self.package_manager == 'choco':
            # Chocolatey doesn't require regular updates
            return True
        else:
            logger.warning("Package manager not supported for system update")
            return False

    def install_system_dependencies(self) -> bool:
        """
        Install system dependencies.

        Returns:
            bool: True if all installations were successful, False otherwise
        """
        if self.skip_system_packages:
            logger.info("Skipping system dependencies (--skip-system-packages)")
            return True

        logger.info("Installing system dependencies...")

        # Define packages for different package managers
        dependencies = {
            'apt': [
                # Essential Tools and Utilities
                "curl", "wget", "tar", "unzip", "jq", "bat", "screen",
                # Text Editors
                "vim", "nano",
                # Node.js and Ruby Environments
                "npm", "nodejs", "ruby",
                # Network Utilities and Libraries
                "libpcap-dev", "git", "nmap", "whatweb", "nikto", "masscan", "netcat",
                # Build essentials
                "build-essential", "python3-dev", "python3-pip"
            ],
            'yum': [
                "curl", "wget", "tar", "unzip", "jq", "bat", "screen",
                "vim", "nano",
                "npm", "nodejs", "ruby",
                "libpcap-devel", "git", "nmap", "nikto", "masscan", "nc",
                "gcc", "gcc-c++", "make", "python3-devel", "python3-pip"
            ],
            'dnf': [
                "curl", "wget", "tar", "unzip", "jq", "bat", "screen",
                "vim", "nano",
                "npm", "nodejs", "ruby",
                "libpcap-devel", "git", "nmap", "nikto", "masscan", "nc",
                "gcc", "gcc-c++", "make", "python3-devel", "python3-pip"
            ],
            'pacman': [
                "curl", "wget", "tar", "unzip", "jq", "bat", "screen",
                "vim", "nano",
                "npm", "nodejs", "ruby",
                "libpcap", "git", "nmap", "nikto", "masscan", "openbsd-netcat",
                "base-devel", "python", "python-pip"
            ],
            'brew': [
                "curl", "wget", "gnu-tar", "jq", "bat", "screen",
                "vim", "nano",
                "node", "npm", "ruby",
                "nmap", "nikto", "masscan", "netcat",
                "python"
            ],
            'choco': [
                "curl", "wget", "jq", "bat",
                "vim", "nano",
                "nodejs", "ruby",
                "nmap", "git", "python"
            ]
        }

        # Get dependencies for current package manager
        packages = dependencies.get(self.package_manager, [])
        if not packages:
            logger.warning(f"No package definitions for {self.package_manager}")
            return False

        # Install packages
        all_success = True

        for package in packages:
            success = self.install_system_package(package)
            if success:
                self.installed_tools['system_packages'].append(package)
            else:
                self.failed_tools['system_packages'].append(package)
                all_success = False

        # Additional package manager specific installations
        if self.package_manager == 'apt':
            # Install ffuf if available
            self.install_system_package("ffuf")

            # Install amass if available
            self.install_system_package("amass")

        # Install npm global packages
        if shutil.which('npm'):
            npm_packages = ["parallel", "wappalyzer"]
            for package in npm_packages:
                success, stdout, stderr = self.run_command(f"npm install -g {package}")
                if success:
                    logger.info(f"Installed npm package: {package}")
                    self.installed_tools['system_packages'].append(f"npm:{package}")
                else:
                    logger.warning(f"Failed to install npm package: {package}")
                    self.failed_tools['system_packages'].append(f"npm:{package}")
                    all_success = False

        return all_success

    def install_system_package(self, package: str) -> bool:
        """
        Install a system package.

        Args:
            package: Package name

        Returns:
            bool: True if successful, False otherwise
        """
        install_commands = {
            'apt': f"apt-get install -y {package}",
            'yum': f"yum install -y {package}",
            'dnf': f"dnf install -y {package}",
            'pacman': f"pacman -S --noconfirm {package}",
            'brew': f"brew install {package}",
            'choco': f"choco install -y {package}"
        }

        command = install_commands.get(self.package_manager)
        if not command:
            logger.warning(f"Package manager {self.package_manager} not supported")
            return False

        logger.info(f"Installing {package}...")
        success, stdout, stderr = self.run_command(command, check=False)

        if success:
            logger.info(f"Installed {package}")
            return True
        else:
            logger.warning(f"Failed to install {package}")
            logger.debug(f"Error: {stderr}")
            return False

    def install_python_tools(self) -> bool:
        """
        Install Python tools with pip.

        Returns:
            bool: True if successful, False otherwise
        """
        if self.skip_python_tools:
            logger.info("Skipping Python tools (--skip-python-tools)")
            return True

        logger.info("Installing Python tools...")

        # Upgrade pip first
        self.run_command("python3 -m pip install --upgrade pip")

        python_tools = [
            "truffleHog", "sublist3r", "uro", "corscanner", "cors", "dnsgen",
            "jsbeautifier", "arjun", "py-altdns", "wfuzz", "httpx"
        ]

        all_success = True

        for tool in python_tools:
            success, stdout, stderr = self.run_command(f"python3 -m pip install {tool}")
            if success:
                logger.info(f"Installed Python tool: {tool}")
                self.installed_tools['python_tools'].append(tool)
            else:
                logger.warning(f"Failed to install Python tool: {tool}")
                self.failed_tools['python_tools'].append(tool)
                all_success = False

        return all_success

    def install_go(self) -> bool:
        """
        Install Go programming language.

        Returns:
            bool: True if successful, False otherwise
        """
        if self.skip_go_tools:
            logger.info("Skipping Go installation (--skip-go-tools)")
            return True

        # Check if Go is already installed
        if shutil.which('go') and not self.force_install:
            try:
                success, stdout, stderr = self.run_command("go version")
                if success:
                    logger.info(f"Go is already installed: {stdout.strip()}")
                    return True
            except Exception:
                pass

        logger.info("Installing Go programming language...")

        go_version = "1.22.4"
        go_install_success = False

        # Try to install using package manager first
        if self.package_manager in ['apt', 'yum', 'dnf', 'pacman', 'brew']:
            success = self.install_system_package('golang')
            if success:
                go_install_success = True

        # If package manager installation failed or not available, install from binary
        if not go_install_success:
            if self.os_type in ['linux', 'ubuntu', 'debian', 'kali', 'centos', 'fedora', 'arch']:
                go_tar = f"go{go_version}.linux-amd64.tar.gz"
                download_url = f"https://go.dev/dl/{go_tar}"
            elif self.os_type == 'darwin':
                go_tar = f"go{go_version}.darwin-amd64.tar.gz"
                download_url = f"https://go.dev/dl/{go_tar}"
            elif self.os_type == 'windows':
                go_zip = f"go{go_version}.windows-amd64.zip"
                download_url = f"https://go.dev/dl/{go_zip}"
            else:
                logger.error(f"Unsupported OS for Go installation: {self.os_type}")
                return False

            # Download Go
            temp_dir = tempfile.mkdtemp()
            temp_file = os.path.join(temp_dir, os.path.basename(download_url))

            logger.info(f"Downloading Go {go_version}...")
            success, stdout, stderr = self.run_command(f"wget {download_url} -O {temp_file}")

            if not success:
                logger.error("Failed to download Go")
                return False

            # Install Go
            if self.os_type in ['linux', 'ubuntu', 'debian', 'kali', 'centos', 'fedora', 'arch', 'darwin']:
                logger.info("Extracting Go...")
                success, stdout, stderr = self.run_command(
                    f"sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf {temp_file}")
                if success:
                    go_install_success = True
            elif self.os_type == 'windows':
                # Windows installation is more complex, recommend manual installation
                logger.info("For Windows, please install Go manually from https://golang.org/dl/")
                return False

            # Clean up
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass

        if go_install_success:
            # Verify installation
            success, stdout, stderr = self.run_command("go version")
            if success:
                logger.info(f"Go installed successfully: {stdout.strip()}")
                self.installed_tools['other_tools'].append('golang')
                return True
            else:
                logger.error("Failed to verify Go installation")
                self.failed_tools['other_tools'].append('golang')
                return False
        else:
            logger.error("Failed to install Go")
            self.failed_tools['other_tools'].append('golang')
            return False

    def install_go_tools(self) -> bool:
        """
        Install Go tools.

        Returns:
            bool: True if all installations were successful, False otherwise
        """
        if self.skip_go_tools:
            logger.info("Skipping Go tools (--skip-go-tools)")
            return True

        # Check if Go is installed
        if not shutil.which('go'):
            logger.error("Go is not installed. Cannot install Go tools.")
            return False

        logger.info("Installing Go tools...")

        # Define Go tools to install
        go_tools = [
            # Subdomain Enumeration
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
            "github.com/gwen001/github-subdomains",
            "github.com/tomnomnom/assetfinder",
            "github.com/projectdiscovery/dnsx/cmd/dnsx",
            "github.com/projectdiscovery/shuffledns/cmd/shuffledns",
            "github.com/haccer/subjack",  # Subdomain takeover detection

            # Live Subdomains and HTTP Probing
            "github.com/tomnomnom/httprobe",
            "github.com/projectdiscovery/httpx/cmd/httpx",

            # URL Discovery
            "github.com/tomnomnom/waybackurls",
            "github.com/lc/gau/v2/cmd/gau",
            "github.com/projectdiscovery/katana/cmd/katana",
            "github.com/hakluke/hakrawler",
            "github.com/003random/getJS",  # Extracting JavaScript files
            "github.com/lc/subjs",  # Extracting JavaScript files from URLs

            # Port Scanning
            "github.com/projectdiscovery/naabu/v2/cmd/naabu",

            # XSS and Other Vulnerability Detection
            "github.com/Emoe/kxss",  # Finding reflected XSS
            "github.com/hahwul/dalfox/v2",  # XSS scanning
            "github.com/tomnomnom/qsreplace",  # Query string replacement

            # Automation and Notification
            "github.com/projectdiscovery/notify/cmd/notify",  # Notification for recon results
            "github.com/ferreiraklet/Jeeves",  # Task automation tool

            # Data Parsing and Extraction
            "github.com/tomnomnom/anew",  # Append new content
            "github.com/tomnomnom/gf",  # Good Finds for regex patterns
            "github.com/tomnomnom/unfurl",  # URL parsing
            "github.com/tomnomnom/gron",  # JSON manipulation

            # Web Scraping and Crawling
            "github.com/jaeles-project/gospider",  # Web crawler
            "github.com/detectify/page-fetch",  # Fetch HTML/JS from web pages

            # Additional Tools
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei",  # Vulnerability scanning
            "github.com/projectdiscovery/chaos-client/cmd/chaos",  # Internet-wide dataset
        ]

        all_success = True

        # Install each tool
        for tool in go_tools:
            logger.info(f"Installing {tool}...")
            success, stdout, stderr = self.run_command(f"go install {tool}@latest")

            if success:
                logger.info(f"Installed Go tool: {tool}")
                self.installed_tools['go_tools'].append(tool)
            else:
                logger.warning(f"Failed to install Go tool: {tool}")
                logger.debug(f"Error: {stderr}")
                self.failed_tools['go_tools'].append(tool)
                all_success = False

        return all_success

    def install_git_tool(self, repo: str) -> bool:
        """
        Clone and install a Git repository.

        Args:
            repo: Repository URL or path

        Returns:
            bool: True if successful, False otherwise
        """
        # Extract tool name from repo
        tool_name = repo.split('/')[-1]
        tool_path = self.tools_dir / "git" / tool_name

        logger.info(f"Installing {tool_name} from {repo}...")

        # Clone the repository
        if tool_path.exists() and not self.force_install:
            logger.info(f"{tool_name} already exists, updating...")
            success, stdout, stderr = self.run_command(f"git -C {tool_path} pull")
        else:
            # Remove existing directory if force install
            if tool_path.exists() and self.force_install:
                shutil.rmtree(tool_path)

            # Clone the repository
            success, stdout, stderr = self.run_command(f"git clone https://{repo}.git {tool_path}")

        if not success:
            logger.warning(f"Failed to clone/update {repo}")
            logger.debug(f"Error: {stderr}")
            self.failed_tools['git_tools'].append(repo)
            return False

        # Install Python dependencies if requirements.txt exists
        requirements_file = tool_path / "requirements.txt"
        if requirements_file.exists():
            success, stdout, stderr = self.run_command(f"python3 -m pip install -r {requirements_file}")
            if not success:
                logger.warning(f"Failed to install dependencies for {tool_name}")
                logger.debug(f"Error: {stderr}")

        logger.info(f"Installed {tool_name}")
        self.installed_tools['git_tools'].append(repo)
        return True

    def install_git_tools(self) -> bool:
        """
        Install tools from Git repositories.

        Returns:
            bool: True if all installations were successful, False otherwise
        """
        if self.skip_git_tools:
            logger.info("Skipping Git tools (--skip-git-tools)")
            return True

        logger.info("Installing tools from Git repositories...")

        # Define Git repositories to clone
        git_repos = [
            # API and Key Scanning
            "github.com/ozguralp/gmapsapiscanner",  # Google Maps API scanner
            "github.com/m4ll0k/SecretFinder",  # Secret/key finder in JS files

            # Subdomain and Asset Discovery
            "github.com/m4ll0k/BBTz",  # Bug bounty tools and utilities

            # NoSQL Injection Scanning
            "github.com/codingo/NoSQLMap",  # Automated NoSQL injection discovery

            # XSS and SQL Injection Scanning
            "github.com/stamparm/DSSS",  # SQL injection scanning tool
            "github.com/r0oth3x49/ghauri",  # Advanced SQL injection tool

            # JavaScript File Scanning and Secret Finding
            "github.com/KathanP19/JSFScan.sh",  # JavaScript file scanner
        ]

        all_success = True

        for repo in git_repos:
            success = self.install_git_tool(repo)
            if not success:
                all_success = False

        return all_success

    def update_shell_config(self) -> bool:
        """
        Update shell configuration files with PATH and aliases.

        Returns:
            bool: True if successful, False otherwise
        """
        logger.info("Updating shell configuration...")

        # Determine home directory
        home_dir = Path.home()

        # Paths to check and update
        shell_configs = {
            'bash': home_dir / '.bashrc',
            'zsh': home_dir / '.zshrc',
            'fish': home_dir / '.config' / 'fish' / 'config.fish'
        }

        # Export paths and aliases to add
        exports = [
            'export PATH=$PATH:/usr/local/go/bin:~/go/bin',
            f'export RECONX_HOME={self.tools_dir.parent / "reconx"}'
        ]

        aliases = [
            'alias reconx="python3 $RECONX_HOME/reconx.py"'
        ]

        success = False

        for shell, config_file in shell_configs.items():
            if config_file.exists():
                logger.info(f"Updating {shell} configuration at {config_file}")

                try:
                    # Read the existing config
                    with open(config_file, 'r') as f:
                        content = f.read()

                    updates_needed = []

                    # Check which exports and aliases need to be added
                    for export in exports:
                        if export not in content:
                            updates_needed.append(export)

                    for alias in aliases:
                        if alias not in content:
                            updates_needed.append(alias)

                    # Add any missing configurations
                    if updates_needed:
                        with open(config_file, 'a') as f:
                            f.write("\n\n# Added by reconX installer\n")
                            for update in updates_needed:
                                f.write(f"{update}\n")

                        logger.info(f"Updated {shell} configuration")
                    else:
                        logger.info(f"{shell} configuration already up to date")

                    success = True

                except Exception as e:
                    logger.warning(f"Failed to update {shell} configuration: {e}")

        if not success:
            logger.warning("Could not update any shell configuration files")
            logger.info("You may need to manually update your shell configuration with the following:")
            for export in exports:
                logger.info(f"  {export}")
            for alias in aliases:
                logger.info(f"  {alias}")

        return success

    def install_aquatone(self) -> bool:
        """
        Install Aquatone.

        Returns:
            bool: True if successful, False otherwise
        """
        logger.info("Installing Aquatone...")

        # Check if Aquatone is already installed
        if shutil.which('aquatone') and not self.force_install:
            logger.info("Aquatone is already installed")
            self.installed_tools['other_tools'].append('aquatone')
            return True

        # Set up paths
        aquatone_dir = self.tools_dir / "bin" / "aquatone"
        aquatone_bin = self.tools_dir / "bin" / "aquatone" / "aquatone"

        # Create directory
        aquatone_dir.mkdir(exist_ok=True)

        # Determine platform-specific download URL
        if self.os_type in ['linux', 'ubuntu', 'debian', 'kali', 'centos', 'fedora', 'arch']:
            download_url = "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip"
        elif self.os_type == 'darwin':
            download_url = "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_macos_amd64_1.7.0.zip"
        elif self.os_type == 'windows':
            download_url = "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_windows_amd64_1.7.0.zip"
        else:
            logger.error(f"Unsupported OS for Aquatone installation: {self.os_type}")
            self.failed_tools['other_tools'].append('aquatone')
            return False

        # Download
        success, stdout, stderr = self.run_command(f"wget {download_url} -O {aquatone_dir}/aquatone.zip")
        if not success:
            logger.error("Failed to download Aquatone")
            self.failed_tools['other_tools'].append('aquatone')
            return False

        # Extract
        success, stdout, stderr = self.run_command(f"unzip -o {aquatone_dir}/aquatone.zip -d {aquatone_dir}")
        if not success:
            logger.error("Failed to extract Aquatone")
            self.failed_tools['other_tools'].append('aquatone')
            return False

        # Make executable
        if aquatone_bin.exists():
            os.chmod(aquatone_bin, 0o755)

            # Create symbolic link
            bin_dir = Path.home() / "go" / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)

            try:
                symlink_path = bin_dir / "aquatone"
                if symlink_path.exists() or os.path.islink(symlink_path):
                    os.unlink(symlink_path)
                os.symlink(aquatone_bin, symlink_path)
                logger.info("Aquatone installed successfully")
                self.installed_tools['other_tools'].append('aquatone')
                return True
            except Exception as e:
                logger.warning(f"Failed to create symbolic link for Aquatone: {e}")
                logger.info("You may need to manually add Aquatone to your PATH")
                self.installed_tools['other_tools'].append('aquatone')
                return True
        else:
            logger.error("Aquatone binary not found after extraction")
            self.failed_tools['other_tools'].append('aquatone')
            return False

    def install_xray(self) -> bool:
        """
        Install Xray vulnerability scanner.

        Returns:
            bool: True if successful, False otherwise
        """
        logger.info("Installing Xray...")

        # Set up paths
        xray_dir = self.tools_dir / "bin" / "xray"

        # Create directory
        xray_dir.mkdir(exist_ok=True)

        # Determine platform-specific download URL
        if self.os_type in ['linux', 'ubuntu', 'debian', 'kali', 'centos', 'fedora', 'arch']:
            download_url = "https://github.com/chaitin/xray/releases/download/1.9.4/xray_linux_amd64.zip"
        elif self.os_type == 'darwin':
            download_url = "https://github.com/chaitin/xray/releases/download/1.9.4/xray_darwin_amd64.zip"
        elif self.os_type == 'windows':
            download_url = "https://github.com/chaitin/xray/releases/download/1.9.4/xray_windows_amd64.zip"
        else:
            logger.error(f"Unsupported OS for Xray installation: {self.os_type}")
            self.failed_tools['other_tools'].append('xray')
            return False

        # Download
        success, stdout, stderr = self.run_command(f"wget {download_url} -O {xray_dir}/xray.zip")
        if not success:
            logger.error("Failed to download Xray")
            self.failed_tools['other_tools'].append('xray')
            return False

        # Extract
        success, stdout, stderr = self.run_command(f"unzip -o {xray_dir}/xray.zip -d {xray_dir}")
        if not success:
            logger.error("Failed to extract Xray")
            self.failed_tools['other_tools'].append('xray')
            return False

        # Make executable
        xray_bin = xray_dir / "xray_linux_amd64"
        if self.os_type == 'darwin':
            xray_bin = xray_dir / "xray_darwin_amd64"
        elif self.os_type == 'windows':
            xray_bin = xray_dir / "xray_windows_amd64.exe"

        if xray_bin.exists():
            os.chmod(xray_bin, 0o755)

            # Create symbolic link
            bin_dir = Path.home() / "go" / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)

            try:
                symlink_path = bin_dir / "xray"
                if symlink_path.exists() or os.path.islink(symlink_path):
                    os.unlink(symlink_path)
                os.symlink(xray_bin, symlink_path)
                logger.info("Xray installed successfully")
                self.installed_tools['other_tools'].append('xray')
                return True
            except Exception as e:
                logger.warning(f"Failed to create symbolic link for Xray: {e}")
                logger.info("You may need to manually add Xray to your PATH")
                self.installed_tools['other_tools'].append('xray')
                return True
        else:
            logger.error("Xray binary not found after extraction")
            self.failed_tools['other_tools'].append('xray')
            return False

    def generate_installation_report(self) -> None:
        """Generate a report of the installation."""
        report_file = self.logs_dir / "installation_report.json"

        # Gather installation statistics
        stats = {
            'timestamp': datetime.now().isoformat(),
            'duration': time.time() - self.stats['start_time'],
            'os': self.os_type,
            'package_manager': self.package_manager,
            'installed_tools': {
                'system_packages': len(self.installed_tools['system_packages']),
                'go_tools': len(self.installed_tools['go_tools']),
                'python_tools': len(self.installed_tools['python_tools']),
                'git_tools': len(self.installed_tools['git_tools']),
                'other_tools': len(self.installed_tools['other_tools']),
                'total': (
                        len(self.installed_tools['system_packages']) +
                        len(self.installed_tools['go_tools']) +
                        len(self.installed_tools['python_tools']) +
                        len(self.installed_tools['git_tools']) +
                        len(self.installed_tools['other_tools'])
                )
            },
            'failed_tools': {
                'system_packages': len(self.failed_tools['system_packages']),
                'go_tools': len(self.failed_tools['go_tools']),
                'python_tools': len(self.failed_tools['python_tools']),
                'git_tools': len(self.failed_tools['git_tools']),
                'other_tools': len(self.failed_tools['other_tools']),
                'total': (
                        len(self.failed_tools['system_packages']) +
                        len(self.failed_tools['go_tools']) +
                        len(self.failed_tools['python_tools']) +
                        len(self.failed_tools['git_tools']) +
                        len(self.failed_tools['other_tools'])
                )
            },
            'installed_tool_details': self.installed_tools,
            'failed_tool_details': self.failed_tools
        }

        # Save report
        with open(report_file, 'w') as f:
            json.dump(stats, f, indent=4)

        logger.info(f"Installation report saved to {report_file}")

        # Print summary
        logger.info("\n" + "=" * 50)
        logger.info("reconX INSTALLATION SUMMARY")
        logger.info("=" * 50)
        logger.info(f"Operating System: {self.os_type}")
        logger.info(f"Package Manager: {self.package_manager}")
        logger.info(f"Installation Duration: {stats['duration']:.2f} seconds")
        logger.info("\nInstalled Tools:")
        logger.info(f"  System Packages: {stats['installed_tools']['system_packages']}")
        logger.info(f"  Go Tools: {stats['installed_tools']['go_tools']}")
        logger.info(f"  Python Tools: {stats['installed_tools']['python_tools']}")
        logger.info(f"  Git Tools: {stats['installed_tools']['git_tools']}")
        logger.info(f"  Other Tools: {stats['installed_tools']['other_tools']}")
        logger.info(f"  Total: {stats['installed_tools']['total']}")

        if stats['failed_tools']['total'] > 0:
            logger.info("\nFailed Tools:")
            logger.info(f"  System Packages: {stats['failed_tools']['system_packages']}")
            logger.info(f"  Go Tools: {stats['failed_tools']['go_tools']}")
            logger.info(f"  Python Tools: {stats['failed_tools']['python_tools']}")
            logger.info(f"  Git Tools: {stats['failed_tools']['git_tools']}")
            logger.info(f"  Other Tools: {stats['failed_tools']['other_tools']}")
            logger.info(f"  Total: {stats['failed_tools']['total']}")

            logger.info("\nSome tools failed to install. Check the installation report for details.")
            logger.info(f"Log file: {self.log_file}")
        else:
            logger.info("\nAll tools installed successfully!")

        logger.info("\nNext Steps:")
        logger.info("1. Restart your terminal or run 'source ~/.bashrc' (or your shell's config file)")
        logger.info("2. Run 'reconx --help' to see available options")
        logger.info("3. Start your reconnaissance with 'reconx -d example.com --full'")
        logger.info("=" * 50)

    def install_tools(self) -> bool:
        """
        Coordinate the installation of all necessary tools.

        Returns:
            bool: True if installation was largely successful, False otherwise
        """
        # Track start time
        self.stats = {'start_time': time.time()}

        # Create tool directories
        self.create_tool_directories()

        # Update system and install dependencies
        system_updated = self.update_system()
        dependencies_installed = self.install_system_dependencies()

        # Install Go
        go_installed = self.install_go()

        # Install Python tools
        python_tools_installed = self.install_python_tools()

        # Install Go tools if Go is installed
        go_tools_installed = False
        if go_installed or shutil.which('go'):
            go_tools_installed = self.install_go_tools()

        # Install Git tools
        git_tools_installed = self.install_git_tools()

        # Install additional tools
        aquatone_installed = self.install_aquatone()
        xray_installed = self.install_xray()

        # Update shell configuration
        shell_updated = self.update_shell_config()

        # Generate installation report
        self.generate_installation_report()

        # Return overall success status
        return (system_updated and dependencies_installed and
                (go_installed or shutil.which('go')) and
                python_tools_installed and go_tools_installed and
                git_tools_installed)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="reconX Installer - Install all dependencies and tools",
        epilog="Example: python3 install.py --verbose"
    )

    parser.add_argument('-d', '--directory', help="Custom directory to install tools")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('--force', action='store_true', help="Force reinstallation of existing tools")

    # Feature selection
    feature_group = parser.add_argument_group('Feature Selection')
    feature_group.add_argument('--skip-system-packages', action='store_true',
                               help="Skip installation of system packages")
    feature_group.add_argument('--skip-go-tools', action='store_true',
                               help="Skip installation of Go tools")
    feature_group.add_argument('--skip-python-tools', action='store_true',
                               help="Skip installation of Python tools")
    feature_group.add_argument('--skip-git-tools', action='store_true',
                               help="Skip installation of Git tools")

    return parser.parse_args()


def main() -> int:
    """Main function."""
    args = parse_args()

    # Set up tool directory if specified
    tools_dir = None
    if args.directory:
        tools_dir = Path(args.directory)

    try:
        # Create and run the system manager
        manager = SystemManager(
            tools_dir=tools_dir,
            verbose=args.verbose,
            force_install=args.force,
            skip_system_packages=args.skip_system_packages,
            skip_go_tools=args.skip_go_tools,
            skip_python_tools=args.skip_python_tools,
            skip_git_tools=args.skip_git_tools
        )

        success = manager.install_tools()
        return 0 if success else 1

    except KeyboardInterrupt:
        logger.info("Installation interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())