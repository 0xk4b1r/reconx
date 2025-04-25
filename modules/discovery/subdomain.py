#!/usr/bin/env python3
"""
subdomain.py - Subdomain enumeration module for reconX

This module performs comprehensive subdomain enumeration using multiple tools
and techniques, including Subfinder, Assetfinder, and optional additional sources.

Author: @0xk4b1r
License: MIT
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from typing import Set, List, Optional
import time
import json
import concurrent.futures
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('subfinder')

# Default paths
DEFAULT_OUTPUT_DIR = Path('./test/output')
DEFAULT_WORDLIST = Path('/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt')


class SubdomainEnumerator:
    """Class for performing subdomain enumeration using various tools."""

    def __init__(self, domain: str, output_dir: Path = None,
                 wordlist: Path = None, threads: int = 10,
                 timeout: int = 600):
        """
        Initialize the subdomain enumerator.

        Args:
            domain: Target domain to enumerate subdomains for
            output_dir: Directory to store results (default: ./test/output/<domain>)
            wordlist: Optional wordlist for brute forcing (default: None)
            threads: Number of threads for concurrent operations
            timeout: Timeout in seconds for each enumeration method
        """
        self.domain = domain
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR / domain
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.subdomains = set()

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up output files
        self.subfinder_results = self.output_dir / 'subfinder-results.txt'
        self.assetfinder_results = self.output_dir / 'assetfinder-results.txt'
        self.final_results = self.output_dir / 'subdomains.txt'
        self.metadata_file = self.output_dir / 'subdomain_metadata.json'

        # Track the tools that were successfully executed
        self.executed_tools = []

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

    def ensure_commands_exist(self, commands: List[str]) -> List[str]:
        """
        Ensure that required commands are available.

        Args:
            commands: List of command names to check

        Returns:
            List[str]: List of missing commands
        """
        missing = [cmd for cmd in commands if not self.check_command(cmd)]
        if missing:
            logger.error(f"Missing required commands: {', '.join(missing)}")
        return missing

    def run_subfinder(self) -> Set[str]:
        """
        Run subfinder for subdomain enumeration.

        Returns:
            Set[str]: Set of discovered subdomains
        """
        subdomains = set()
        if self.ensure_commands_exist(['subfinder']):
            logger.warning("Skipping subfinder as it's not installed")
            return subdomains

        logger.info(f"Running subfinder on {self.domain}...")
        start_time = time.time()

        try:
            # Run subfinder with various options for better coverage
            cmd = [
                'subfinder',
                '-d', self.domain,
                '-silent',
                '-all',  # Use all sources
                '-timeout', str(self.timeout),
                '-o', str(self.subfinder_results)
            ]

            subprocess.run(cmd, check=True, capture_output=True, text=True)

            # Read the results file if it exists
            if self.subfinder_results.exists():
                with open(self.subfinder_results, 'r') as f:
                    file_content = f.read().splitlines()
                    subdomains.update(file_content)
                logger.info(f"Subfinder found {len(subdomains)} subdomains")
                self.executed_tools.append('subfinder')
            else:
                logger.warning("Subfinder didn't produce any results")

        except subprocess.CalledProcessError as e:
            logger.error(f"Subfinder failed: {e}")
            if e.stderr:
                logger.debug(f"Error details: {e.stderr}")
        except Exception as e:
            logger.error(f"Error running subfinder: {e}")

        elapsed = time.time() - start_time
        logger.info(f"Subfinder completed in {elapsed:.2f} seconds")
        return subdomains

    def run_assetfinder(self) -> Set[str]:
        """
        Run assetfinder for subdomain enumeration.

        Returns:
            Set[str]: Set of discovered subdomains
        """
        subdomains = set()
        if self.ensure_commands_exist(['assetfinder']):
            logger.warning("Skipping assetfinder as it's not installed")
            return subdomains

        logger.info(f"Running assetfinder on {self.domain}...")
        start_time = time.time()

        try:
            # Run assetfinder
            cmd = ['assetfinder', '--subs-only', self.domain]
            process = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True
            )

            # Save output to file and update the set
            output_lines = process.stdout.splitlines()
            with open(self.assetfinder_results, 'w') as f:
                f.write('\n'.join(output_lines))

            subdomains.update(output_lines)
            logger.info(f"Assetfinder found {len(subdomains)} subdomains")
            self.executed_tools.append('assetfinder')

        except subprocess.CalledProcessError as e:
            logger.error(f"Assetfinder failed: {e}")
            if e.stderr:
                logger.debug(f"Error details: {e.stderr}")
        except Exception as e:
            logger.error(f"Error running assetfinder: {e}")

        elapsed = time.time() - start_time
        logger.info(f"Assetfinder completed in {elapsed:.2f} seconds")
        return subdomains

    def run_amass(self) -> Set[str]:
        """
        Run amass for subdomain enumeration (if available).

        Returns:
            Set[str]: Set of discovered subdomains
        """
        subdomains = set()
        if self.ensure_commands_exist(['amass']):
            logger.info("Amass not found, skipping")
            return subdomains

        logger.info(f"Running amass on {self.domain}...")
        start_time = time.time()
        amass_output = self.output_dir / 'amass-results.txt'

        try:
            # Run amass with passive mode for faster results
            cmd = [
                'amass', 'enum',
                '-passive',
                '-d', self.domain,
                '-o', str(amass_output)
            ]

            subprocess.run(cmd, check=True, timeout=self.timeout, capture_output=True)

            # Read the results
            if amass_output.exists():
                with open(amass_output, 'r') as f:
                    file_content = f.read().splitlines()
                    subdomains.update(file_content)
                logger.info(f"Amass found {len(subdomains)} subdomains")
                self.executed_tools.append('amass')
            else:
                logger.warning("Amass didn't produce any results")

        except subprocess.TimeoutExpired:
            logger.warning(f"Amass timed out after {self.timeout} seconds")
        except subprocess.CalledProcessError as e:
            logger.error(f"Amass failed: {e}")
        except Exception as e:
            logger.error(f"Error running amass: {e}")

        elapsed = time.time() - start_time
        logger.info(f"Amass completed in {elapsed:.2f} seconds")
        return subdomains

    def filter_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """
        Filter and clean up subdomain list.

        Args:
            subdomains: Set of subdomains to filter

        Returns:
            Set[str]: Set of filtered and validated subdomains
        """
        filtered = set()
        for subdomain in subdomains:
            # Basic validation
            subdomain = subdomain.strip().lower()

            # Skip empty or invalid entries
            if not subdomain or ' ' in subdomain:
                continue

            # Ensure it's related to the main domain
            if not (subdomain.endswith(f'.{self.domain}') or subdomain == self.domain):
                continue

            filtered.add(subdomain)

        return filtered

    def save_results(self) -> int:
        """
        Save all discovered subdomains to the output file.

        Returns:
            int: Number of unique subdomains saved
        """
        # Filter and clean the subdomains
        filtered_subdomains = self.filter_subdomains(self.subdomains)

        # Sort the subdomains alphabetically for readability
        sorted_subdomains = sorted(filtered_subdomains)

        # Save to the output file
        with open(self.final_results, 'w') as f:
            f.write('\n'.join(sorted_subdomains))

        # Save metadata
        metadata = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'total_subdomains': len(sorted_subdomains),
            'tools_used': self.executed_tools,
            'execution_time': time.time() - self.start_time
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)

        return len(sorted_subdomains)

    def enumerate(self) -> Set[str]:
        """
        Perform full subdomain enumeration using all available methods.

        Returns:
            Set[str]: Set of all discovered subdomains
        """
        self.start_time = time.time()
        logger.info(f"Starting subdomain enumeration for {self.domain}")

        # Run all enumeration methods
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            tasks = {
                executor.submit(self.run_subfinder): 'subfinder',
                executor.submit(self.run_assetfinder): 'assetfinder',
                executor.submit(self.run_amass): 'amass'
            }

            for future in concurrent.futures.as_completed(tasks):
                tool = tasks[future]
                try:
                    subdomains = future.result()
                    self.subdomains.update(subdomains)
                    logger.debug(f"{tool} found {len(subdomains)} subdomains")
                except Exception as e:
                    logger.error(f"Error in {tool}: {e}")

        # Save results
        total_subdomains = self.save_results()

        elapsed = time.time() - self.start_time
        logger.info(f"Enumeration completed in {elapsed:.2f} seconds")
        logger.info(f"Found {total_subdomains} unique subdomains for {self.domain}")
        logger.info(f"Results saved to {self.final_results}")

        return self.subdomains


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Subdomain enumeration tool for reconX",
        epilog="Example: python3 subdomain.py example.com --threads 20"
    )

    parser.add_argument('domain', help="Target domain for subdomain enumeration")
    parser.add_argument('-o', '--output', help="Custom output directory")
    parser.add_argument('-w', '--wordlist', help="Custom wordlist for brute forcing")
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help="Number of threads for concurrent operations")
    parser.add_argument('--timeout', type=int, default=600,
                        help="Timeout in seconds for each enumeration method")
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

    # Set up wordlist if specified
    wordlist = None
    if args.wordlist:
        wordlist = Path(args.wordlist)
        if not wordlist.exists():
            logger.error(f"Wordlist not found: {wordlist}")
            return 1

    try:
        # Create and run the enumerator
        enumerator = SubdomainEnumerator(
            domain=args.domain,
            output_dir=output_dir,
            wordlist=wordlist,
            threads=args.threads,
            timeout=args.timeout
        )

        subdomains = enumerator.enumerate()
        return 0 if subdomains else 1

    except KeyboardInterrupt:
        logger.info("Enumeration interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())