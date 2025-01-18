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
    """Create directory for storing subdomains."""
    output_dir = os.path.join('./output', domain)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def run_subdomain_tools(domain):
    """Run subdomain enumeration tools."""
    output_dir = create_directory(domain)
    subfinder_file = 'subfinder-subdomains.txt'
    assetfinder_file = 'assetfinder-subdomains.txt'
    subdomains = set()

    # Run Subfinder
    try:
        subfinder_output = subprocess.check_output(['subfinder', '-d', domain, '-silent'], text=True).splitlines()
        subdomains.update(subfinder_output)
    except subprocess.CalledProcessError as e:
        print(f"Subfinder failed: {e}")

    # Run Assetfinder
    try:
        assetfinder_output = subprocess.check_output(['assetfinder', '--subs-only', domain], text=True).splitlines()
        subdomains.update(assetfinder_output)
    except subprocess.CalledProcessError as e:
        print(f"Assetfinder failed: {e}")

    # Save unique subdomains
    all_subdomains_file = os.path.join(output_dir, 'subdomains.txt')

    with open(all_subdomains_file, 'w') as f:
        f.write("\n".join(sorted(subdomains)))

    return all_subdomains_file

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
    parser.add_argument('domain', help="Target domain for subdomain enumeration")
    args = parser.parse_args()

    domain = args.domain

    # Ensure required tools are installed
    required_commands = ['subfinder', 'assetfinder']
    ensure_commands_exist(required_commands)

    # Create output directory and run tools
    run_subdomain_tools(domain)
    print("Subdomain enumeration completed!")

if __name__ == '__main__':
    main()