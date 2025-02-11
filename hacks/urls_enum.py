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
    output_dir = os.path.join('./test/output', domain)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def run_urls_enum(domain, output_dir):
    """Find and enumerate URLs using various tools."""
    subdomains_file = os.path.join(output_dir, 'subdomains.txt')
    urls_file = os.path.join(output_dir, 'urls.txt')

    if not os.path.exists(subdomains_file):
        print(f"Subdomains file not found: {subdomains_file}")
        sys.exit(1)

    with open(subdomains_file, 'r') as f:
        subdomains = f.read().splitlines()

    all_urls = []

    for subdomain in subdomains:
        try:
            print(f"Running waybackurls for {subdomain}")
            output = subprocess.check_output(['waybackurls', subdomain], text=True).splitlines()
            all_urls.extend(output)
        except subprocess.CalledProcessError as e:
            print(f"Waybackurls failed for {subdomain}: {e}")

    with open(urls_file, 'w') as f:
        f.write("\n".join(all_urls))



def main():
    parser = argparse.ArgumentParser(description="URL enumeration tool")
    parser.add_argument('domain', help="Target domain for URL enumeration")
    args = parser.parse_args()

    domain = args.domain

    # Ensure required tools are installed
    required_commands = ['waybackurls']
    ensure_commands_exist(required_commands)

    # Create output directory and run URL enumeration
    output_dir = create_directory(domain)
    run_urls_enum(domain, output_dir)
    print("URL enumeration completed!")

if __name__ == '__main__':
    main()