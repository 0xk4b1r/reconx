import os
import subprocess
import sys
import argparse
from collections import defaultdict

def check_command(command):
    """Check if a command is available in the system."""
    result = subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def ensure_commands_exist(commands):
    """Ensure that all required commands are available."""
    missing = [cmd for cmd in commands if not check_command(cmd)]
    if missing:
        print(f"Missing required commands: {', '.join(missing)}")
        sys.exit(1)

def create_directory(domain):
    """Create directory for storing nmap output."""
    output_dir = os.path.join('./test/output', domain)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def run_nmap_scan(domain, output_dir):
    """Run nmap scan."""
    ports_file = os.path.join(output_dir, 'ports.txt')
    nmap_file = os.path.join(output_dir, 'nmap.txt')

    nmap_output = ""

    if not os.path.exists(ports_file):
        print(f"Ports file not found: {ports_file}")
        sys.exit(1)

    subdomain_ports = defaultdict(list)
    with open(ports_file, 'r') as f:
        for line in f:
            subdomain, port = line.strip().split(":")
            subdomain_ports[subdomain].append(port)

    for subdomain, ports in subdomain_ports.items():
        ports_str = ",".join(ports)
        try:
            output = subprocess.check_output(['nmap', '-p', ports_str, subdomain], text=True)
            nmap_output += output
            print(f"Scanning {subdomain} on ports {ports_str}:\n{output}")
        except subprocess.CalledProcessError as e:
            print(f"Error scanning {subdomain} on ports {ports_str}: {e}")

    with open(nmap_file, 'w') as f:
        f.write(nmap_output)

def main():
    parser = argparse.ArgumentParser(description="Nmap scan tool")
    parser.add_argument('domain', help="Target domain for nmap scan")
    args = parser.parse_args()

    domain = args.domain

    required_commands = ['nmap']
    ensure_commands_exist(required_commands)

    output_dir = create_directory(domain)
    run_nmap_scan(domain, output_dir)

if __name__ == '__main__':
    main()