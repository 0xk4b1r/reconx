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
    """Create directory for storing URLs."""
    output_dir = os.path.join('./output', domain, 'urls')
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def run_command(command, output_file=None):
    """Run a shell command and write its output to a file if provided."""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        if output_file:
            with open(output_file, 'a') as f:
                f.write(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while running: {command}\nError: {e}")
        return ""

def enumerate_urls(domain, output_dir):
    """Find and enumerate URLs using various tools."""
    waybackurls_file = os.path.join(output_dir, 'waybackurls-urls.txt')
    gau_file = os.path.join(output_dir, 'gau-urls.txt')
    katana_file = os.path.join(output_dir, 'katana-urls.txt')
    hakrawler_file = os.path.join(output_dir, 'hakrawler-urls.txt')

    # Finding URLs
    run_command(f"echo {domain} | waybackurls", waybackurls_file)
    # run_command(f"echo {domain} | gau", gau_file)
    # run_command(f"echo {domain} | katana", katana_file)
    # run_command(f"echo {domain} | hakrawler", hakrawler_file)

    # Combine and filter URLs
    all_urls_file = os.path.join(output_dir, 'urls.txt')
    combined_urls = f"cat {output_dir}/*-urls.txt | grep -Eo '(http|https)://[a-zA-Z0-9./?=_-]*' | sort -u"
    run_command(combined_urls, all_urls_file)

    # Filter URLs with uro
    filtered_urls_file = os.path.join(output_dir, 'filtered-urls.txt')
    run_command(f"cat {all_urls_file} | uro", filtered_urls_file)

    # Filter URLs with parameters
    param_urls_file = os.path.join(output_dir, 'param-urls.txt')
    if os.path.exists(filtered_urls_file) and os.path.getsize(filtered_urls_file) > 0:
        run_command(f"cat {filtered_urls_file} | grep '='", param_urls_file)

    # Check live URLs using httpx
    live_filtered_urls_file = os.path.join(output_dir, 'live-filtered-urls.txt')
    run_command(f"cat {filtered_urls_file} | httpx", live_filtered_urls_file)

    # Live URLs with parameters
    live_param_urls_file = os.path.join(output_dir, 'live-param-urls.txt')
    if os.path.exists(live_filtered_urls_file) and os.path.getsize(live_filtered_urls_file) > 0:
        run_command(f"cat {live_filtered_urls_file} | grep '='", live_param_urls_file)

def main():
    parser = argparse.ArgumentParser(description="URL enumeration tool")
    parser.add_argument('domain', help="Target domain for URL enumeration")
    args = parser.parse_args()

    domain = args.domain

    # Ensure required tools are installed
    required_commands = ['waybackurls', 'uro', 'httpx']
    ensure_commands_exist(required_commands)

    # Create output directory and run URL enumeration
    output_dir = create_directory(domain)
    enumerate_urls(domain, output_dir)
    print("URL enumeration completed!")

if __name__ == '__main__':
    main()