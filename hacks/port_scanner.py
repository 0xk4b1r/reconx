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
    """Run port scan using naabu."""
    ports_file = os.path.join(output_dir, 'ports.txt')

    try:
        output = subprocess.check_output(['naabu', '-host', domain], text=True).splitlines()
        with open(ports_file, 'w') as f:
            f.write("\n".join(output))
    except subprocess.CalledProcessError as e:
        print(f"Naabu failed: {e}")

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
    print("Port scanning completed!")

if __name__ == '__main__':
    main()