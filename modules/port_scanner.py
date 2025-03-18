#!/usr/bin/env python3
"""
port_scanner.py - Port scanning module for reconX

This module performs port scanning on discovered subdomains using naabu
and provides options for customizing scan parameters.

Author: @0xk4b1r
License: MIT
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
import time
import json
import concurrent.futures
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('port_scanner')


class PortScanner:
    """Class for performing port scanning on discovered subdomains."""

    def __init__(self, domain: str, output_dir: Optional[Path] = None,
                 threads: int = 10, timeout: int = 600,
                 ports: Optional[str] = None, rate: int = 1000,
                 scan_top_ports: bool = False):
        """
        Initialize the port scanner.

        Args:
            domain: Target domain
            output_dir: Directory to store results (default: ./test/output/<domain>)
            threads: Number of threads for concurrent operations
            timeout: Timeout in seconds for the scan operations
            ports: Custom ports to scan (e.g., "80,443,8080-8090")
            rate: Number of packets per second (for naabu)
            scan_top_ports: Whether to scan only top ports
        """
        self.domain = domain
        self.output_dir = output_dir or Path('./test/output') / domain
        self.threads = threads
        self.timeout = timeout
        self.ports = ports
        self.rate = rate
        self.scan_top_ports = scan_top_ports

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up input and output files
        self.subdomains_file = self.output_dir / 'subdomains.txt'
        self.ports_file = self.output_dir / 'ports.txt'
        self.json_results_file = self.output_dir / 'ports.json'
        self.metadata_file = self.output_dir / 'port_scan_metadata.json'

        # Track scan statistics
        self.scan_stats = {
            'total_subdomains': 0,
            'scanned_subdomains': 0,
            'open_ports_found': 0,
            'start_time': time.time(),
            'scan_duration': 0,
            'errors': []
        }

    def check_command(self, command: str) -> bool:
        """
        Check if a command is available in the system.

        Args:
            command: The command to check

        Returns:
            bool: True if the command exists, False otherwise
        """
        result = subprocess.run(
            ['which', command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return result.returncode == 0

    def ensure_commands_exist(self, commands: List[str]) -> bool:
        """
        Ensure that required commands are available.

        Args:
            commands: List of command names to check

        Returns:
            bool: True if all commands exist, False otherwise
        """
        missing = [cmd for cmd in commands if not self.check_command(cmd)]
        if missing:
            logger.error(f"Missing required commands: {', '.join(missing)}")
            return False
        return True

    def load_subdomains(self) -> List[str]:
        """
        Load subdomains from the subdomain file.

        Returns:
            List[str]: List of subdomains to scan
        """
        if not self.subdomains_file.exists():
            logger.error(f"Subdomains file not found: {self.subdomains_file}")
            return []

        with open(self.subdomains_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]

        logger.info(f"Loaded {len(subdomains)} subdomains for port scanning")
        self.scan_stats['total_subdomains'] = len(subdomains)
        return subdomains

    def scan_subdomain(self, subdomain: str) -> List[Tuple[str, int]]:
        """
        Scan ports on a single subdomain using naabu.

        Args:
            subdomain: The subdomain to scan

        Returns:
            List[Tuple[str, int]]: List of (subdomain, port) tuples with open ports
        """
        results = []

        try:
            cmd = ['naabu', '-host', subdomain, '-json']

            # Add optional parameters if provided
            if self.ports:
                cmd.extend(['-p', self.ports])
            elif self.scan_top_ports:
                cmd.extend(['-top-ports', '100'])

            cmd.extend(['-rate', str(self.rate)])
            cmd.extend(['-c', str(self.threads)])

            logger.debug(f"Running: {' '.join(cmd)}")

            process = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Process naabu JSON output
            for line in process.stdout.splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        if 'host' in data and 'port' in data:
                            results.append((data['host'], data['port']))
                    except json.JSONDecodeError:
                        logger.debug(f"Invalid JSON from naabu: {line}")

            # Update scan stats
            self.scan_stats['scanned_subdomains'] += 1
            self.scan_stats['open_ports_found'] += len(results)

            # Log progress
            logger.info(f"Scanned {subdomain}: found {len(results)} open ports")

        except subprocess.CalledProcessError as e:
            error_msg = f"Naabu failed for {subdomain}: {e}"
            logger.error(error_msg)
            self.scan_stats['errors'].append(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = f"Scan timed out for {subdomain} after {self.timeout} seconds"
            logger.warning(error_msg)
            self.scan_stats['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error scanning {subdomain}: {str(e)}"
            logger.error(error_msg)
            self.scan_stats['errors'].append(error_msg)

        return results

    def run_scan(self) -> Dict[str, List[int]]:
        """
        Run port scan on all subdomains.

        Returns:
            Dict[str, List[int]]: Dictionary mapping subdomains to lists of open ports
        """
        if not self.ensure_commands_exist(['naabu']):
            logger.error("Naabu not installed. Port scanning cannot proceed.")
            return {}

        # Load subdomains
        subdomains = self.load_subdomains()
        if not subdomains:
            return {}

        scan_results = {}
        all_results = []

        logger.info(f"Starting port scan on {len(subdomains)} subdomains")
        start_time = time.time()

        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
            future_to_subdomain = {
                executor.submit(self.scan_subdomain, subdomain): subdomain
                for subdomain in subdomains
            }

            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    results = future.result()
                    if results:
                        # Group results by subdomain
                        for host, port in results:
                            if host not in scan_results:
                                scan_results[host] = []
                            scan_results[host].append(port)
                            all_results.append(f"{host}:{port}")
                except Exception as e:
                    logger.error(f"Error processing results for {subdomain}: {e}")

        # Update scan duration
        self.scan_stats['scan_duration'] = time.time() - start_time

        # Save all ports to the output file
        with open(self.ports_file, 'w') as f:
            f.write('\n'.join(all_results))

        # Save detailed results as JSON
        with open(self.json_results_file, 'w') as f:
            json.dump(scan_results, f, indent=4)

        # Save metadata
        self.save_metadata()

        logger.info(f"Port scan completed in {self.scan_stats['scan_duration']:.2f} seconds")
        logger.info(f"Found {len(all_results)} open ports across {len(scan_results)} subdomains")
        logger.info(f"Results saved to {self.ports_file} and {self.json_results_file}")

        return scan_results

    def save_metadata(self) -> None:
        """Save scan metadata to a JSON file."""
        metadata = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'scan_stats': self.scan_stats,
            'scan_parameters': {
                'threads': self.threads,
                'timeout': self.timeout,
                'ports': self.ports,
                'scan_top_ports': self.scan_top_ports,
                'rate': self.rate
            }
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Port scanning module for reconX",
        epilog="Example: python3 port_scanner.py example.com --ports 80,443,8080-8090"
    )

    parser.add_argument('domain', help="Target domain for port scanning")
    parser.add_argument('-o', '--output', help="Custom output directory")
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help="Number of threads for concurrent operations")
    parser.add_argument('--timeout', type=int, default=600,
                        help="Timeout in seconds for each scan operation")
    parser.add_argument('-p', '--ports', help="Custom ports to scan (e.g., '80,443,8080-8090')")
    parser.add_argument('--top-ports', action='store_true',
                        help="Scan only top 100 ports")
    parser.add_argument('--rate', type=int, default=1000,
                        help="Number of packets per second")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Enable verbose output")

    return parser.parse_args()


def main() -> int:
    """Main function."""
    args = parse_args()

    # Set logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        # Update all handlers
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)

    # Set up output directory if specified
    output_dir = None
    if args.output:
        output_dir = Path(args.output)

    try:
        # Create and run the port scanner
        scanner = PortScanner(
            domain=args.domain,
            output_dir=output_dir,
            threads=args.threads,
            timeout=args.timeout,
            ports=args.ports,
            rate=args.rate,
            scan_top_ports=args.top_ports
        )

        results = scanner.run_scan()
        return 0 if results else 1

    except KeyboardInterrupt:
        logger.info("Port scanning interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())