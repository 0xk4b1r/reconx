import os
import subprocess
import sys
from multiprocessing.pool import job_counter
from tabnanny import check


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


def enumerate_web_technologies(subdomains_file, output_dir):
    """Enumerate web technologies using WhatWeb."""
    whatweb_file = os.path.join(output_dir, 'whatweb.txt')
    print(subdomains_file)
    try:
        subprocess.run(['whatweb','-i', subdomains_file, '--log-brief', whatweb_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running WhatWeb: {e}")


def capture_web_screenshots(subdomains_file, output_dir):
    """Capture screenshots of web pages using Aquatone."""

    screenshot_dir = os.path.join(output_dir, 'screenshots')
    chromium_path = subprocess.run(['which', 'chromium'], stdout=subprocess.PIPE, text=True).stdout.strip()

    if not chromium_path:
        print("Chromium not found, skipping screenshot capture.")
        return

    try:
        with open(subdomains_file, 'r') as f:
            subdomains = f.read().splitlines()
        subprocess.run(['aquatone', '-chrome-path', chromium_path, '-out', screenshot_dir, *subdomains], check=True)


    except subprocess.CalledProcessError as e:
        print(f"Error running Aquatone: {e}")


def scan_with_nikto(subdomains_file, output_dir):
    """Scan with Nikto."""
    nikto_dir = os.path.join(output_dir, 'nikto')
    os.makedirs(nikto_dir, exist_ok=True)  # Ensure the directory exists

    try:
        with open(subdomains_file, 'r') as f:
            subdomains = f.read().splitlines()
            for subdomain in subdomains:
                sub = subdomain.replace('http://', '').replace('https://', '')
                output_file = os.path.join(nikto_dir, f"{sub}.txt")
                subprocess.run(['nikto', '-h', subdomain], stdout=open(output_file, 'w'), check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error running Nikto: {e}")
    except FileNotFoundError as e:
        print(f"File not found: {e}")


def main(domain):
    subdomains_file = os.path.join('./output',domain, 'subdomains.txt')

    output_dir = create_directory(domain)
    # enumerate_web_technologies(subdomains_file, output_dir)
    # capture_web_screenshots(subdomains_file, output_dir)
    scan_with_nikto(subdomains_file, output_dir)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 web_enum.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    main(domain)




