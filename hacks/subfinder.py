import os
import subprocess
import logging
import sys

# Logging setup
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def check_command(command):
    """Check if a command is available in the system."""
    result = subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def ensure_commands_exist(commands):
    """Ensure that all required commands are available."""
    missing = [cmd for cmd in commands if not check_command(cmd)]
    if missing:
        logging.error(f"Missing required commands: {', '.join(missing)}")
        sys.exit(1)

def create_directory(domain):
    """Create directory for storing subdomains."""
    output_dir = os.path.join('./output', domain)
    os.makedirs(output_dir, exist_ok=True)
    logging.info(f"Output directory: {output_dir}")
    return output_dir

def run_subdomain_tools(domain, output_dir):
    """Run subdomain enumeration tools."""
    subdomains_file = os.path.join(output_dir, 'subdomains.txt')
    subdomains = set()

    # Run Subfinder
    try:
        logging.info("Running Subfinder...")
        output = subprocess.check_output(['subfinder', '-d', domain, '-silent'], text=True).splitlines()
        subdomains.update(output)
    except subprocess.CalledProcessError as e:
        logging.error(f"Subfinder failed: {e}")

    # Run Assetfinder
    try:
        logging.info("Running Assetfinder...")
        output = subprocess.check_output(['assetfinder', '--subs-only', domain], text=True).splitlines()
        subdomains.update(output)
    except subprocess.CalledProcessError as e:
        logging.error(f"Assetfinder failed: {e}")

    # Save unique subdomains
    with open(subdomains_file, 'w') as f:
        f.write("\n".join(sorted(subdomains)))
    logging.info(f"Subdomains saved to {subdomains_file}")

    return subdomains_file

def main():
    if len(sys.argv) < 2:
        logging.error("Usage: python subfinder.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    # Ensure required tools are installed
    required_commands = ['subfinder', 'assetfinder']
    ensure_commands_exist(required_commands)

    # Create output directory and run tools
    output_dir = create_directory(domain)
    run_subdomain_tools(domain, output_dir)
    logging.info("Subdomain enumeration completed!")

if __name__ == '__main__':
    main()
