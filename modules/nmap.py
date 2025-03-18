#!/usr/bin/env python3
"""
nmap.py - Nmap scanning module for reconX

This module performs detailed port scanning and service fingerprinting using Nmap
on previously discovered open ports. It processes the port scan results from
the port_scanner.py module and provides comprehensive information about services
running on the target infrastructure.

Author: @0xk4b1r
License: MIT
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Union, Tuple
import time
import json
import concurrent.futures
from datetime import datetime
from collections import defaultdict
import re
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('nmap_scanner')


class NmapScanner:
    """Class for performing Nmap scans on discovered ports."""

    def __init__(self, domain: str, output_dir: Optional[Path] = None,
                 threads: int = 5, timeout: int = 3600,
                 scan_intensity: str = 'normal',
                 additional_args: Optional[List[str]] = None):
        """
        Initialize the Nmap scanner.

        Args:
            domain: Target domain
            output_dir: Directory to store results (default: ./test/output/<domain>)
            threads: Number of concurrent scans
            timeout: Timeout in seconds for each scan
            scan_intensity: Scan intensity level (normal, aggressive, light)
            additional_args: Additional Nmap arguments
        """
        self.domain = domain
        self.output_dir = output_dir or Path('./test/output') / domain
        self.threads = threads
        self.timeout = timeout
        self.scan_intensity = scan_intensity
        self.additional_args = additional_args or []

        # Set scan parameters based on intensity
        self.scan_params = self._get_scan_parameters()

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up input and output files
        self.ports_file = self.output_dir / 'ports.txt'
        self.nmap_output_dir = self.output_dir / 'nmap'
        self.nmap_summary_file = self.output_dir / 'nmap_summary.txt'
        self.nmap_json_file = self.output_dir / 'nmap_results.json'
        self.nmap_xml_file = self.output_dir / 'nmap_results.xml'
        self.metadata_file = self.output_dir / 'nmap_metadata.json'

        # Ensure Nmap output directory exists
        self.nmap_output_dir.mkdir(exist_ok=True)

        # Stats tracking
        self.stats = {
            'total_hosts': 0,
            'scanned_hosts': 0,
            'total_ports': 0,
            'start_time': time.time(),
            'duration': 0,
            'errors': []
        }

        # Store results
        self.scan_results = defaultdict(dict)

    def _get_scan_parameters(self) -> List[str]:
        """
        Get Nmap scan parameters based on intensity level.

        Returns:
            List[str]: List of Nmap parameters
        """
        # Base scan parameters
        params = ['-v', '--open']

        # Add parameters based on intensity
        if self.scan_intensity == 'aggressive':
            params.extend(['-A', '-T4', '--script=default,discovery,vuln'])
        elif self.scan_intensity == 'light':
            params.extend(['-sV', '--version-intensity=2', '-T3'])
        else:  # normal
            params.extend(['-sV', '-sC', '-T3'])

        # Add any custom parameters
        params.extend(self.additional_args)

        return params

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

    def load_ports(self) -> Dict[str, List[str]]:
        """
        Load ports from the ports file.

        Returns:
            Dict[str, List[str]]: Dictionary mapping hostnames to ports
        """
        if not self.ports_file.exists():
            logger.error(f"Ports file not found: {self.ports_file}")
            return {}

        subdomain_ports = defaultdict(list)

        with open(self.ports_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue

                try:
                    subdomain, port = line.split(':', 1)
                    subdomain_ports[subdomain].append(port)
                except ValueError:
                    logger.warning(f"Invalid line in ports file: {line}")

        # Update stats
        self.stats['total_hosts'] = len(subdomain_ports)
        self.stats['total_ports'] = sum(len(ports) for ports in subdomain_ports.values())

        logger.info(f"Loaded {self.stats['total_ports']} ports across {self.stats['total_hosts']} hosts")

        return subdomain_ports

    def scan_host(self, host: str, ports: List[str]) -> Dict:
        """
        Run Nmap scan on a specific host with specified ports.

        Args:
            host: The hostname or IP to scan
            ports: List of ports to scan

        Returns:
            Dict: Scan results for the host
        """
        results = {
            'host': host,
            'ports': [],
            'services': {},
            'os': None,
            'hostname': None,
            'scripts': {},
            'success': False,
            'error': None
        }

        # Create a unique output file name for this host
        host_safe = host.replace('.', '_').replace(':', '_')
        xml_output = self.nmap_output_dir / f"{host_safe}_nmap.xml"

        # Prepare ports string
        ports_str = ','.join(ports)

        try:
            # Prepare Nmap command
            cmd = ['nmap', '-p', ports_str, host, '-oX', str(xml_output)]
            cmd.extend(self.scan_params)

            logger.info(
                f"Scanning {host} on {len(ports)} ports: {ports_str[:50]}{'...' if len(ports_str) > 50 else ''}")
            logger.debug(f"Running: {' '.join(cmd)}")

            # Run Nmap scan
            process = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Parse XML output if it exists
            if xml_output.exists():
                try:
                    results.update(self._parse_nmap_xml(xml_output))
                    results['success'] = True
                except Exception as e:
                    logger.error(f"Error parsing Nmap XML for {host}: {e}")
                    results['error'] = f"XML parsing error: {str(e)}"
            else:
                logger.warning(f"Nmap XML output not found for {host}")
                results['error'] = "XML output not found"

            # Update stats
            self.stats['scanned_hosts'] += 1

            # Calculate and log progress
            progress = (self.stats['scanned_hosts'] / self.stats['total_hosts']) * 100
            logger.info(f"Progress: {progress:.1f}% ({self.stats['scanned_hosts']}/{self.stats['total_hosts']})")

        except subprocess.CalledProcessError as e:
            error_msg = f"Nmap scan failed for {host}: {e}"
            logger.error(error_msg)
            if e.stderr:
                logger.debug(f"Error details: {e.stderr}")
            results['error'] = error_msg
            self.stats['errors'].append(error_msg)

        except subprocess.TimeoutExpired:
            error_msg = f"Nmap scan timed out for {host} after {self.timeout} seconds"
            logger.warning(error_msg)
            results['error'] = error_msg
            self.stats['errors'].append(error_msg)

        except Exception as e:
            error_msg = f"Error scanning {host}: {str(e)}"
            logger.error(error_msg)
            results['error'] = error_msg
            self.stats['errors'].append(error_msg)

        return results

    def _parse_nmap_xml(self, xml_file: Path) -> Dict:
        """
        Parse Nmap XML output.

        Args:
            xml_file: Path to the Nmap XML file

        Returns:
            Dict: Parsed scan results
        """
        results = {
            'ports': [],
            'services': {},
            'os': None,
            'hostname': None,
            'scripts': {}
        }

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Extract hostnames
            hostnames = root.findall('./host/hostnames/hostname')
            if hostnames:
                results['hostname'] = hostnames[0].get('name')

            # Extract OS information
            os_match = root.findall('./host/os/osmatch')
            if os_match:
                results['os'] = {
                    'name': os_match[0].get('name'),
                    'accuracy': os_match[0].get('accuracy')
                }

            # Extract port information
            ports = root.findall('./host/ports/port')
            for port in ports:
                port_id = port.get('portid')
                protocol = port.get('protocol')

                # Get service information
                service = port.find('service')
                service_info = {
                    'port': port_id,
                    'protocol': protocol,
                    'state': port.find('state').get('state'),
                    'service': service.get('name') if service is not None else 'unknown',
                    'product': service.get('product') if service is not None else None,
                    'version': service.get('version') if service is not None else None
                }

                # Add port to list
                results['ports'].append(port_id)

                # Add service info
                results['services'][port_id] = service_info

                # Extract script output
                scripts = port.findall('script')
                if scripts:
                    script_results = {}
                    for script in scripts:
                        script_id = script.get('id')
                        script_output = script.get('output')
                        script_results[script_id] = script_output

                    results['scripts'][port_id] = script_results

        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
            raise

        return results

    def run_scans(self) -> Dict:
        """
        Run Nmap scans on all hosts.

        Returns:
            Dict: Dictionary containing all scan results
        """
        if not self.check_command('nmap'):
            logger.error("Nmap not installed. Scanning cannot proceed.")
            return {}

        # Load ports
        subdomain_ports = self.load_ports()
        if not subdomain_ports:
            logger.error("No ports found for scanning")
            return {}

        logger.info(f"Starting Nmap scans on {len(subdomain_ports)} hosts with intensity: {self.scan_intensity}")
        start_time = time.time()

        # Run scans in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_host = {
                executor.submit(self.scan_host, host, ports): host
                for host, ports in subdomain_ports.items()
            }

            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    results = future.result()
                    if results['success']:
                        self.scan_results[host] = results
                except Exception as e:
                    logger.error(f"Error processing results for {host}: {e}")

        # Update duration
        self.stats['duration'] = time.time() - start_time

        # Save results
        self.save_results()

        logger.info(f"Nmap scanning completed in {self.stats['duration']:.2f} seconds")
        logger.info(f"Successfully scanned {len(self.scan_results)} hosts")
        if self.stats['errors']:
            logger.warning(f"Encountered {len(self.stats['errors'])} errors during scanning")

        return self.scan_results

    def save_results(self) -> None:
        """Save scan results to output files."""
        # Save detailed JSON results
        with open(self.nmap_json_file, 'w') as f:
            json.dump(self.scan_results, f, indent=4)

        # Save summary
        with open(self.nmap_summary_file, 'w') as f:
            f.write(f"Nmap Scan Summary for {self.domain}\n")
            f.write(f"=================================\n\n")
            f.write(f"Scan completed: {datetime.now().isoformat()}\n")
            f.write(f"Scan duration: {self.stats['duration']:.2f} seconds\n")
            f.write(f"Hosts scanned: {self.stats['scanned_hosts']}/{self.stats['total_hosts']}\n\n")

            # Write host summaries
            for host, data in self.scan_results.items():
                f.write(f"Host: {host}\n")
                f.write(f"{'=' * (len(host) + 6)}\n")

                if data.get('hostname'):
                    f.write(f"Hostname: {data['hostname']}\n")

                if data.get('os'):
                    f.write(f"OS: {data['os']['name']} (Accuracy: {data['os']['accuracy']}%)\n")

                f.write(f"Open Ports: {len(data['ports'])}\n\n")

                # Write service information
                f.write("Services:\n")
                f.write("---------\n")
                for port, service in data['services'].items():
                    service_str = f"{port}/{service['protocol']}: {service['service']}"
                    if service['product']:
                        service_str += f" - {service['product']}"
                    if service['version']:
                        service_str += f" {service['version']}"
                    f.write(f"{service_str}\n")

                f.write("\n\n")

        # Save metadata
        metadata = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'scan_parameters': {
                'intensity': self.scan_intensity,
                'threads': self.threads,
                'timeout': self.timeout,
                'nmap_args': ' '.join(self.scan_params)
            }
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)

        logger.info(f"Results saved to {self.nmap_json_file}")
        logger.info(f"Summary saved to {self.nmap_summary_file}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Nmap scanning module for reconX",
        epilog="Example: python3 nmap.py example.com --intensity aggressive"
    )

    parser.add_argument('domain', help="Target domain for Nmap scanning")
    parser.add_argument('-o', '--output', help="Custom output directory")
    parser.add_argument('-t', '--threads', type=int, default=5,
                        help="Number of concurrent scans (default: 5)")
    parser.add_argument('--timeout', type=int, default=3600,
                        help="Timeout in seconds for each scan (default: 3600)")
    parser.add_argument('--intensity', choices=['light', 'normal', 'aggressive'],
                        default='normal', help="Scan intensity level (default: normal)")
    parser.add_argument('--nmap-args', help="Additional Nmap arguments")
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

    # Parse additional Nmap arguments if specified
    additional_args = []
    if args.nmap_args:
        additional_args = args.nmap_args.split()

    try:
        # Create and run the Nmap scanner
        scanner = NmapScanner(
            domain=args.domain,
            output_dir=output_dir,
            threads=args.threads,
            timeout=args.timeout,
            scan_intensity=args.intensity,
            additional_args=additional_args
        )

        results = scanner.run_scans()
        return 0 if results else 1

    except KeyboardInterrupt:
        logger.info("Nmap scanning interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())