import os
import subprocess


class SystemManager:
    def __init__(self):
        self.tools_dir = os.path.expanduser("~/tools")
        self.kit_dir = os.path.dirname(self.tools_dir)

    def run_command(self, command, check=True):
        """Run a shell command."""
        try:
            subprocess.run(command, check=check, shell=True)
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while running: '{command}'\nError: {e}")

    def update_system(self):
        self.run_command("apt-get -y update")

    def install_dependencies(self):
        dependencies = [
            # Essential Tools and Utilities
            "curl", "wget", "tar", "unzip", "jq", "bat", "screen",

            # Text Editors
            "vim", "nano",

            # Node.js and Ruby Environments
            "npm", "nodejs", "ruby",

            # Network Utilities and Libraries
            "libpcap-dev", "git", "nmap", "whatweb", "sqlmap", "nikto", "masscan", "netcat", "ffuf", "amass", "dnsutils",
        ]

        # Command to install system dependencies
        self.run_command(f"apt-get install -y {' '.join(dependencies)}")

        # NPM global installations for JavaScript and HTTP-related tooling
        self.run_command("npm install -g parallel")
        self.run_command("npm install -g wappalyzer")

        # Pip3 global installations for Python-based security tools
        self.run_command("pip install --upgrade pip")
        self.run_command("pip install uro corscanner cors dnsgen jsbeautifier arjun")

        # Optional: pip-based tools for vulnerability discovery and exploitation
        self.run_command("pip install truffleHog")
        self.run_command("pip install sublist3r")
        self.run_command("pip install searchsploit")

    def create_tool_directories(self):
        """Create the necessary directories for tools."""
        os.makedirs(self.tools_dir, exist_ok=True)

    def install_go(self):
        """Install Go programming language."""
        go_version = "1.22.4"
        go_tar = f"go{go_version}.linux-amd64.tar.gz"
        self.run_command(f"wget https://go.dev/dl/{go_tar} -P {self.tools_dir}")
        self.run_command(f"sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf {self.tools_dir}/{go_tar}")
        self.run_command(f"rm {self.tools_dir}/{go_tar}")

    def install_go_tools(self, tools):
        """Install specified Go tools."""
        for tool in tools:
            self.run_command(f"go install {tool}@latest")

    def install_git_tool(self, repo):
        """Clone a Git repository and install its Python dependencies."""
        tool_name = os.path.basename(repo)
        tool_path = os.path.join(self.tools_dir, tool_name)

        # Clone the repository
        self.run_command(f"git clone https://{repo}.git {tool_path}")

        # Install Python dependencies if requirements.txt exists
        requirements_file = os.path.join(tool_path, "requirements.txt")
        if os.path.exists(requirements_file):
            self.run_command(f"pip3 install -r {requirements_file}")

    def reconage_config(self):
        """Update .bashrc and .zshrc with PATH and alias for reconage."""
        for shell in ['hacks', 'zsh']:
            shellrc = os.path.expanduser(f"~/.{shell}rc")
            with open(shellrc, "a") as file:
                file.write('export PATH=$PATH:/usr/local/go/bin:~/go/bin\n')
                file.write("alias reconage='~/reconage/reconage.sh'\n")

    def install_aquatone(self):
        """Install Aquatone."""
        aquatone_dir = os.path.join(self.tools_dir, "aquatone")
        os.makedirs(aquatone_dir, exist_ok=True)
        self.run_command(f"cd {aquatone_dir} && wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip")
        self.run_command(f"cd {aquatone_dir} && unzip aquatone_linux_amd64_1.7.0.zip")
        self.run_command("sudo mv aquatone ~/go/bin/")
        print("Aquatone installed successfully.")

    def install_xray(self):
        """Install Xray."""
        xray_dir = os.path.join(self.tools_dir, "xray")
        os.makedirs(xray_dir, exist_ok=True)
        self.run_command(f"cd {xray_dir} && wget https://github.com/chaitin/xray/releases/download/1.9.4/xray_linux_amd64.zip")
        self.run_command(f"cd {xray_dir} && unzip xray_linux_amd64.zip")
        print("Xray installed successfully.")

    def install_tools(self):
        """Coordinate the installation of all necessary tools."""
        self.update_system()
        self.install_dependencies()
        self.create_tool_directories()
        self.install_go()

        # List of Go tools to install
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

            # Additional Tools for Expanding Recon and Pentesting
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei",  # Vulnerability scanning using templates
            "github.com/projectdiscovery/chaos-client/cmd/chaos",  # Internet-wide dataset for reconnaissance
        ]
        self.install_go_tools(go_tools)

        # Install Git tools
        git_tools = [
            # API and Key Scanning
            "github.com/ozguralp/gmapsapiscanner",  # Google Maps API scanner
            "github.com/m4ll0k/SecretFinder",  # Secret/key finder in JS files

            # Subdomain and Asset Discovery
            "github.com/m4ll0k/BBTz",  # Bug bounty tools and utilities

            # NoSQL Injection Scanning
            "github.com/codingo/NoSQLMap",  # Automated NoSQL injection discovery

            # XSS and SQL Injection Scanning
            "github.com/stamparm/DSSS",  # SQL injection scanning tool
            "github.com/r0oth3x49/ghauri",  # Advanced SQL injection tool with error-based detection

            # JavaScript File Scanning and Secret Finding
            "github.com/KathanP19/JSFScan.sh",  # JavaScript file scanner
        ]
        for repo in git_tools:
            self.install_git_tool(repo)

        # Install additional tools like aquatone and xray
        self.install_aquatone()
        self.install_xray()

        self.reconage_config()


def main():
    manager = SystemManager()
    manager.install_tools()


if __name__ == "__main__":
    main()
