import os
import subprocess
import sys
import argparse


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
    """Create directory for storing port scan results."""
    output_dir = os.path.join('./output', domain)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def run_port_scan(domain, output_dir):
    """Run port scan using naabu on all subdomains."""
    subdomains_file = os.path.join(output_dir, 'subdomains.txt')
    ports_file = os.path.join(output_dir, 'ports.txt')

    if not os.path.exists(subdomains_file):
        print(f"Subdomains file not found: {subdomains_file}")
        sys.exit(1)

    with open(subdomains_file, 'r') as f:
        subdomains = f.read().splitlines()

    all_ports = []

    for subdomain in subdomains:
        try:
            output = subprocess.check_output(['naabu', '-host', subdomain], text=True).splitlines()
            all_ports.extend(output)
        except subprocess.CalledProcessError as e:
            print(f"Naabu failed for {subdomain}: {e}")

    with open(ports_file, 'w') as f:
        f.write("\n".join(all_ports))

    return ports_file


def main():
    parser = argparse.ArgumentParser(description="Port scanning tool using naabu")
    parser.add_argument('domain', help="Target domain for port scanning")
    args = parser.parse_args()

    domain = args.domain

    # Ensure required tools are installed
    required_commands = ['naabu']
    ensure_commands_exist(required_commands)

    # Create output directory and run port scan
    output_dir = create_directory(domain)
    run_port_scan(domain, output_dir)



if __name__ == '__main__':
    main()