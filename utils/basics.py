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