#!/usr/bin/env python3
"""
web_enum.py - Web enumeration module for reconX

This module performs comprehensive web enumeration on discovered subdomains, 
including technology detection, screenshot capturing, and vulnerability scanning.
It provides valuable information about web technologies, visual confirmation of 
active web services, and potential security issues.

Author: @0xk4b1r
License: MIT
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Union, Tuple, Any
import time
import json
import concurrent.futures
import shutil
from datetime import datetime
import tempfile
import re
import csv
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('web_enum')


class WebEnumerator:
    """Class for performing web enumeration on discovered subdomains."""

    def __init__(self, domain: str, output_dir: Optional[Path] = None,
                 threads: int = 5, timeout: int = 600,
                 screenshot: bool = True, whatweb: bool = True,
                 nikto: bool = False,
                 chrome_path: Optional[str] = None):
        """
        Initialize the web enumerator.

        Args:
            domain: Target domain
            output_dir: Directory to store results (default: ./test/output/<domain>)
            threads: Number of concurrent operations
            timeout: Timeout in seconds for operations
            screenshot: Whether to capture screenshots
            whatweb: Whether to run WhatWeb
            nikto: Whether to run Nikto (more intensive)
            chrome_path: Path to Chrome/Chromium executable (for screenshots)
        """
        self.domain = domain
        self.output_dir = output_dir or Path('./test/output') / domain
        self.threads = threads
        self.timeout = timeout
        self.run_screenshot = screenshot
        self.run_whatweb = whatweb
        self.run_nikto = nikto
        self.chrome_path = chrome_path

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up input and output files/directories
        self.subdomains_file = self.output_dir / 'subdomains.txt'
        self.whatweb_file = self.output_dir / 'whatweb_results.json'
        self.screenshot_dir = self.output_dir / 'screenshots'
        self.nikto_dir = self.output_dir / 'nikto'
        self.metadata_file = self.output_dir / 'web_enum_metadata.json'
        self.summary_file = self.output_dir / 'web_summary.txt'

        # Create necessary directories
        if self.run_screenshot:
            self.screenshot_dir.mkdir(exist_ok=True)

        if self.run_nikto:
            self.nikto_dir.mkdir(exist_ok=True)

        # Stats tracking
        self.stats = {
            'total_subdomains': 0,
            'processed_subdomains': 0,
            'screenshots_captured': 0,
            'whatweb_processed': 0,
            'nikto_scanned': 0,
            'start_time': time.time(),
            'duration': 0,
            'errors': []
        }

        # Results storage
        self.whatweb_results = {}
        self.nikto_results = {}
        self.screenshot_results = {}

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

    def find_chrome_path(self) -> Optional[str]:
        """
        Find the path to Chrome or Chromium browser.

        Returns:
            Optional[str]: Path to Chrome/Chromium or None if not found
        """
        # Check if explicitly provided
        if self.chrome_path and os.path.exists(self.chrome_path):
            return self.chrome_path

        # Common locations
        chrome_paths = [
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
        ]

        for path in chrome_paths:
            if os.path.exists(path):
                return path

        # Try to find using which
        for browser in ["chromium", "chromium-browser", "google-chrome"]:
            try:
                result = subprocess.run(
                    ["which", browser],
                    check=True,
                    capture_output=True,
                    text=True
                )
                if result.stdout:
                    return result.stdout.strip()
            except subprocess.CalledProcessError:
                pass

        return None

    def load_subdomains(self) -> List[str]:
        """
        Load subdomains from the subdomain file.

        Returns:
            List[str]: List of subdomains
        """
        if not self.subdomains_file.exists():
            logger.error(f"Subdomains file not found: {self.subdomains_file}")
            return []

        with open(self.subdomains_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]

        # Add http:// prefix if missing
        normalized_subdomains = []
        for subdomain in subdomains:
            if not (subdomain.startswith('http://') or subdomain.startswith('https://')):
                normalized_subdomains.append(f"http://{subdomain}")
            else:
                normalized_subdomains.append(subdomain)

        logger.info(f"Loaded {len(normalized_subdomains)} subdomains for web enumeration")
        self.stats['total_subdomains'] = len(normalized_subdomains)
        return normalized_subdomains

    def run_whatweb(self, subdomains: List[str]) -> Dict:
        """
        Run WhatWeb on a list of subdomains.

        Args:
            subdomains: List of subdomains to scan

        Returns:
            Dict: WhatWeb results
        """
        if not self.check_command('whatweb'):
            logger.warning("WhatWeb not found, skipping technology detection")
            return {}

        logger.info("Running WhatWeb for technology detection...")
        start_time = time.time()

        # Create a temporary file with subdomains
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file_path = temp_file.name
            for subdomain in subdomains:
                temp_file.write(f"{subdomain}\n")

        whatweb_results = {}

        try:
            # Run WhatWeb with JSON output
            cmd = [
                'whatweb',
                '--quiet',
                '--no-errors',
                '--log-json', str(self.whatweb_file),
                '-i', temp_file_path
            ]

            logger.debug(f"Running: {' '.join(cmd)}")

            process = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Read the JSON output
            if self.whatweb_file.exists():
                with open(self.whatweb_file, 'r') as f:
                    content = f.read()
                    # Process the JSON lines
                    for line in content.strip().split('\n'):
                        try:
                            entry = json.loads(line)
                            target = entry.get('target')
                            if target:
                                whatweb_results[target] = entry
                        except json.JSONDecodeError:
                            continue

                self.stats['whatweb_processed'] = len(whatweb_results)
                logger.info(f"WhatWeb identified technologies for {len(whatweb_results)} subdomains")
            else:
                logger.warning("WhatWeb did not produce any output")

        except subprocess.CalledProcessError as e:
            error_msg = f"WhatWeb failed: {e}"
            logger.error(error_msg)
            if e.stderr:
                logger.debug(f"Error details: {e.stderr}")
            self.stats['errors'].append(error_msg)

        except subprocess.TimeoutExpired:
            error_msg = f"WhatWeb timed out after {self.timeout} seconds"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)

        except Exception as e:
            error_msg = f"Error running WhatWeb: {str(e)}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)

        finally:
            # Clean up the temporary file
            try:
                os.unlink(temp_file_path)
            except Exception:
                pass

        duration = time.time() - start_time
        logger.info(f"WhatWeb completed in {duration:.2f} seconds")

        return whatweb_results

    def capture_screenshot(self, url: str) -> bool:
        """
        Capture a screenshot of a URL using Aquatone.

        Args:
            url: URL to capture

        Returns:
            bool: True if screenshot was captured successfully, False otherwise
        """
        chrome_path = self.find_chrome_path()
        if not chrome_path:
            logger.warning("Chrome/Chromium not found, skipping screenshot")
            return False

        if not self.check_command('aquatone'):
            logger.warning("Aquatone not found, skipping screenshot")
            return False

        # Extract domain for filename
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        if not hostname:
            hostname = url.replace('http://', '').replace('https://', '').split('/')[0]

        # Ensure hostname is a valid filename
        hostname = re.sub(r'[^\w\-\.]', '_', hostname)

        # Set up output path
        screenshot_path = self.screenshot_dir / f"{hostname}.png"

        try:
            # Create a temporary directory for Aquatone
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a temporary file with the URL
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                    temp_file_path = temp_file.name
                    temp_file.write(f"{url}\n")

                # Run Aquatone
                cmd = [
                    'aquatone',
                    '-chrome-path', chrome_path,
                    '-out', temp_dir,
                    '-silent',
                    '-http-timeout', '10000',
                    '-scan-timeout', '10000',
                    '-screenshot-timeout', '10000',
                    '-ports', 'small',
                    '-screenshot-timeout', '20000',
                    '-no-session',
                    '-input', temp_file_path
                ]

                logger.debug(f"Running: {' '.join(cmd)}")

                process = subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )

                # Find the screenshot in the temporary directory
                screenshot_files = list(Path(temp_dir).glob('screenshots/*.png'))
                if screenshot_files:
                    # Copy the first screenshot to our output directory
                    shutil.copy(screenshot_files[0], screenshot_path)
                    self.screenshot_results[url] = str(screenshot_path)
                    self.stats['screenshots_captured'] += 1
                    logger.debug(f"Screenshot captured for {url}")
                    return True
                else:
                    logger.warning(f"Aquatone did not produce a screenshot for {url}")
                    return False

        except subprocess.CalledProcessError as e:
            error_msg = f"Aquatone failed for {url}: {e}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)
            return False

        except subprocess.TimeoutExpired:
            error_msg = f"Aquatone timed out for {url} after {self.timeout} seconds"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)
            return False

        except Exception as e:
            error_msg = f"Error capturing screenshot for {url}: {str(e)}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)
            return False

        finally:
            # Clean up the temporary file
            try:
                os.unlink(temp_file_path)
            except Exception:
                pass

    def run_nikto(self, url: str) -> Dict:
        """
        Run Nikto vulnerability scanner on a URL.

        Args:
            url: URL to scan

        Returns:
            Dict: Nikto results
        """
        if not self.check_command('nikto'):
            logger.warning("Nikto not found, skipping vulnerability scan")
            return {}

        # Extract domain for filename
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        if not hostname:
            hostname = url.replace('http://', '').replace('https://', '').split('/')[0]

        # Ensure hostname is a valid filename
        hostname = re.sub(r'[^\w\-\.]', '_', hostname)

        # Set up output paths
        nikto_txt_path = self.nikto_dir / f"{hostname}.txt"
        nikto_json_path = self.nikto_dir / f"{hostname}.json"

        results = {
            'url': url,
            'hostname': hostname,
            'findings': [],
            'success': False
        }

        try:
            # Run Nikto with JSON output
            cmd = [
                'nikto',
                '-h', url,
                '-o', str(nikto_json_path),
                '-Format', 'json',
                '-Tuning', '123457890ab',  # All default checks
                '-timeout', '30'  # 30 seconds timeout for connections
            ]

            logger.debug(f"Running: {' '.join(cmd)}")

            # Run Nikto and capture text output
            process = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Save text output
            with open(nikto_txt_path, 'w') as f:
                f.write(process.stdout)

            # Read the JSON output if it exists
            if nikto_json_path.exists():
                try:
                    with open(nikto_json_path, 'r') as f:
                        nikto_data = json.load(f)
                        if 'vulnerabilities' in nikto_data:
                            results['findings'] = nikto_data['vulnerabilities']
                        results['success'] = True
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON output from Nikto for {url}")

            self.stats['nikto_scanned'] += 1
            logger.info(f"Nikto scan completed for {url}")

        except subprocess.CalledProcessError as e:
            error_msg = f"Nikto failed for {url}: {e}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)

        except subprocess.TimeoutExpired:
            error_msg = f"Nikto timed out for {url} after {self.timeout} seconds"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)

        except Exception as e:
            error_msg = f"Error running Nikto on {url}: {str(e)}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)

        return results

    def process_subdomain(self, url: str) -> Dict:
        """
        Process a single subdomain with all selected tools.

        Args:
            url: URL to process

        Returns:
            Dict: Results for this URL
        """
        results = {
            'url': url,
            'screenshot': None,
            'nikto': None
        }

        # Capture screenshot if enabled
        if self.run_screenshot:
            screenshot_success = self.capture_screenshot(url)
            if screenshot_success:
                results['screenshot'] = self.screenshot_results.get(url)

        # Run Nikto if enabled
        if self.run_nikto:
            nikto_results = self.run_nikto(url)
            if nikto_results.get('success'):
                results['nikto'] = nikto_results
                self.nikto_results[url] = nikto_results

        # Update processed count
        self.stats['processed_subdomains'] += 1

        # Log progress
        progress = (self.stats['processed_subdomains'] / self.stats['total_subdomains']) * 100
        logger.info(
            f"Progress: {progress:.1f}% ({self.stats['processed_subdomains']}/{self.stats['total_subdomains']})")

        return results

    def run_enumeration(self) -> Dict:
        """
        Run web enumeration on all subdomains.

        Returns:
            Dict: Enumeration results
        """
        # Load subdomains
        subdomains = self.load_subdomains()
        if not subdomains:
            logger.error("No subdomains found for web enumeration")
            return {}

        results = {}

        logger.info(f"Starting web enumeration on {len(subdomains)} subdomains")
        start_time = time.time()

        # Run WhatWeb if enabled (uses its own parallelism)
        if self.run_whatweb:
            self.whatweb_results = self.run_whatweb(subdomains)

        # Process each subdomain in parallel for other tasks
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {
                executor.submit(self.process_subdomain, url): url
                for url in subdomains
            }

            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results[url] = result
                except Exception as e:
                    logger.error(f"Error processing {url}: {e}")

        # Update stats
        self.stats['duration'] = time.time() - start_time

        # Generate summary
        self.generate_summary(results)

        # Save metadata
        self.save_metadata()

        logger.info(f"Web enumeration completed in {self.stats['duration']:.2f} seconds")
        logger.info(f"Processed {self.stats['processed_subdomains']} subdomains")
        if self.run_whatweb:
            logger.info(f"Identified technologies on {self.stats['whatweb_processed']} subdomains")
        if self.run_screenshot:
            logger.info(f"Captured {self.stats['screenshots_captured']} screenshots")
        if self.run_nikto:
            logger.info(f"Completed {self.stats['nikto_scanned']} Nikto scans")

        return results

    def generate_summary(self, results: Dict) -> None:
        """
        Generate a summary of the web enumeration findings.

        Args:
            results: Enumeration results
        """
        with open(self.summary_file, 'w') as f:
            f.write(f"Web Enumeration Summary for {self.domain}\n")
            f.write(f"====================================\n\n")
            f.write(f"Scan completed: {datetime.now().isoformat()}\n")
            f.write(f"Scan duration: {self.stats['duration']:.2f} seconds\n\n")

            # WhatWeb summary
            if self.run_whatweb and self.whatweb_results:
                f.write("Technology Detection Summary\n")
                f.write("---------------------------\n")
                f.write(f"Technologies detected on {len(self.whatweb_results)} websites\n\n")

                # Count technology occurrences
                technology_count = {}
                for url, data in self.whatweb_results.items():
                    if 'plugins' in data:
                        for tech, info in data['plugins'].items():
                            technology_count[tech] = technology_count.get(tech, 0) + 1

                # Write top technologies
                f.write("Top Technologies:\n")
                for tech, count in sorted(technology_count.items(), key=lambda x: x[1], reverse=True)[:20]:
                    f.write(f"- {tech}: {count}\n")
                f.write("\n")

            # Screenshot summary
            if self.run_screenshot and self.screenshot_results:
                f.write("Screenshot Summary\n")
                f.write("-----------------\n")
                f.write(f"Captured {len(self.screenshot_results)} screenshots\n")
                f.write(f"Screenshots saved to: {self.screenshot_dir}\n\n")

            # Nikto summary
            if self.run_nikto and self.nikto_results:
                f.write("Vulnerability Scan Summary\n")
                f.write("-------------------------\n")
                f.write(f"Scanned {len(self.nikto_results)} websites with Nikto\n\n")

                # Count vulnerability occurrences
                vuln_count = {}
                for url, data in self.nikto_results.items():
                    if 'findings' in data:
                        for finding in data['findings']:
                            vuln_type = finding.get('id', 'Unknown')
                            vuln_count[vuln_type] = vuln_count.get(vuln_type, 0) + 1

                # Write top vulnerabilities
                if vuln_count:
                    f.write("Top Findings:\n")
                    for vuln, count in sorted(vuln_count.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"- {vuln}: {count}\n")
                else:
                    f.write("No vulnerabilities found\n")

                f.write("\n")

    def save_metadata(self) -> None:
        """Save metadata to a JSON file."""
        metadata = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'enabled_features': {
                'whatweb': self.run_whatweb,
                'screenshot': self.run_screenshot,
                'nikto': self.run_nikto
            }
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)

        logger.info(f"Metadata saved to {self.metadata_file}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Web enumeration module for reconX",
        epilog="Example: python3 web_enum.py example.com --screenshot --whatweb"
    )

    parser.add_argument('domain', help="Target domain for web enumeration")
    parser.add_argument('-o', '--output', help="Custom output directory")
    parser.add_argument('-t', '--threads', type=int, default=5,
                        help="Number of concurrent operations (default: 5)")
    parser.add_argument('--timeout', type=int, default=600,
                        help="Timeout in seconds for operations (default: 600)")

    # Tool selection options
    tool_group = parser.add_argument_group('Tool Selection')
    tool_group.add_argument('--no-screenshot', action='store_true',
                            help="Disable screenshot capture")
    tool_group.add_argument('--no-whatweb', action='store_true',
                            help="Disable WhatWeb technology detection")
    tool_group.add_argument('--nikto', action='store_true',
                            help="Enable Nikto vulnerability scanning (slower)")

    # Additional options
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument('--chrome-path',
                            help="Path to Chrome/Chromium executable for screenshots")
    misc_group.add_argument('-v', '--verbose', action='store_true',
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
        # Create and run the web enumerator
        enumerator = WebEnumerator(
            domain=args.domain,
            output_dir=output_dir,
            threads=args.threads,
            timeout=args.timeout,
            screenshot=not args.no_screenshot,
            whatweb=not args.no_whatweb,
            nikto=args.nikto,
            chrome_path=args.chrome_path
        )

        results = enumerator.run_enumeration()
        return 0 if results else 1

    except KeyboardInterrupt:
        logger.info("Web enumeration interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())