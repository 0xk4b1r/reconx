import os
import subprocess
import datetime


class ReconScript:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains_dir = os.path.join(domain, "subdomains")
        self.ports_dir = os.path.join(domain, "open-ports")
        self.ip_converter_script = "~/reconage/hacks/ip-converter.sh"
        self.log_file = "recon_script.log"
        self.create_directory_structure()

    def log(self, message):
        """Log messages with timestamp."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")

    def run_command(self, command, shell=True):
        """Run a shell command and log any errors."""
        try:
            subprocess.run(command, shell=shell, check=True)
        except subprocess.CalledProcessError as e:
            self.log(f"Error running command '{command}': {e}")
            raise

    def create_directory_structure(self):
        """Create directory structure for subdomains and ports."""
        os.makedirs(self.subdomains_dir, exist_ok=True)
        os.makedirs(self.ports_dir, exist_ok=True)
        self.log(f"Created directory structure: {self.subdomains_dir}, {self.ports_dir}")

    def find_ip_addresses(self):
        """Find IP addresses from subdomains."""
        subdomains_file = os.path.join(self.subdomains_dir, "live-subdomains.txt")
        ips_file = os.path.join(self.ports_dir, "ips.txt")

        self.log("Finding IP addresses...")

        # Uncomment to use custom IP converter script
        # self.run_command(f"{self.ip_converter_script} {subdomains_file} {ips_file}")

        # Use dnsx to find IPs
        self.run_command(f"cat {subdomains_file} | dnsx -resp-only -a -silent | anew {ips_file}")
        self.log(f"IP addresses found and saved to: {ips_file}")

    def find_open_ports(self):
        """Find open ports on IP addresses."""
        subdomains_file = os.path.join(self.subdomains_dir, "live-subdomains.txt")
        ips_file = os.path.join(self.ports_dir, "ips.txt")
        ips_ports_file = os.path.join(self.ports_dir, "ips-ports.txt")
        live_ips_ports_file = os.path.join(self.ports_dir, "live-ips-ports.txt")
        hosts_ports_file = os.path.join(self.ports_dir, "hosts-ports-subdomains.txt")
        live_open_ports_file = os.path.join(self.ports_dir, "live-open-ports-subdomains.txt")

        self.log("Finding open ports...")

        # Finding IP:Port combinations
        self.run_command(f"cat {ips_file} | naabu -top-ports 1000 -silent | anew {ips_ports_file}")
        self.run_command(f"cat {ips_ports_file} | httpx -threads 300 -silent | anew {live_ips_ports_file}")

        # Finding Host:Port combinations
        self.run_command(f"cat {subdomains_file} | naabu -top-ports 1000 -silent | anew {hosts_ports_file}")
        self.run_command(f"cat {hosts_ports_file} | httpx -threads 300 -silent | anew {live_open_ports_file}")

        # Copy live-open-ports to subdomains directory
        subprocess.run(
            f"cp {live_open_ports_file} {os.path.join(self.subdomains_dir, 'live-open-ports-subdomains.txt')}",
            shell=True)

        self.log(f"Open ports found and saved to: {self.ports_dir}")

    def push_to_github(self):
        """Push changes to GitHub."""
        self.run_command(f"git add . && git commit -m 'target: {self.domain} | open ports' && git push")
        self.log("Pushed to GitHub successfully")

    def main(self):
        """Run all tasks."""
        self.find_ip_addresses()
        self.find_open_ports()
        self.push_to_github()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python recon_script.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    recon = ReconScript(domain)
    recon.main()
