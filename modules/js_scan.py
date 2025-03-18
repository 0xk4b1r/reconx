#!/usr/bin/env python3
"""
js_scan.py - JavaScript scanning module for reconX

This module discovers, analyzes, and extracts valuable information from JavaScript
files associated with target subdomains. It can identify secrets, API endpoints,
and other sensitive information that might be exposed in JavaScript source code.

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
import tempfile
from datetime import datetime
import re
import requests
from urllib.parse import urlparse
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('js_scanner')


class JSScanner:
    """Class for scanning and analyzing JavaScript files."""

    def __init__(self, domain: str, output_dir: Optional[Path] = None,
                 threads: int = 10, timeout: int = 600,
                 download: bool = True, analyze: bool = True,
                 extract_endpoints: bool = True, extract_secrets: bool = True,
                 user_agent: Optional[str] = None):
        """
        Initialize the JavaScript scanner.

        Args:
            domain: Target domain
            output_dir: Directory to store results (default: ./test/output/<domain>)
            threads: Number of concurrent operations
            timeout: Timeout in seconds for operations
            download: Whether to download JS files
            analyze: Whether to analyze JS content
            extract_endpoints: Whether to extract API endpoints
            extract_secrets: Whether to extract potential secrets
            user_agent: Custom User-Agent for requests
        """
        self.domain = domain
        self.output_dir = output_dir or Path('./test/output') / domain
        self.threads = threads
        self.timeout = timeout
        self.download = download
        self.analyze = analyze
        self.extract_endpoints = extract_endpoints
        self.extract_secrets = extract_secrets
        self.user_agent = user_agent or "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up input and output files/directories
        self.subdomains_file = self.output_dir / 'subdomains.txt'
        self.urls_file = self.output_dir / 'urls.txt'
        self.js_dir = self.output_dir / 'js'
        self.js_files_dir = self.js_dir / 'files'
        self.js_links_file = self.js_dir / 'js_links.txt'
        self.endpoints_file = self.js_dir / 'endpoints.txt'
        self.secrets_file = self.js_dir / 'secrets.txt'
        self.metadata_file = self.js_dir / 'js_scan_metadata.json'
        self.summary_file = self.js_dir / 'js_summary.txt'

        # Create necessary directories
        self.js_dir.mkdir(exist_ok=True)
        if self.download:
            self.js_files_dir.mkdir(exist_ok=True)

        # Regex patterns for analysis
        self.endpoint_patterns = [
            r'(?:"|\'|\`)(?:/[a-zA-Z0-9_?&=/\-\#\.]*)',  # Paths like "/api/v1/users"
            r'(?:"|\'|\`)(?:https?://[a-zA-Z0-9\-\.]+(?:/[a-zA-Z0-9_?&=/\-\#\.]*)?)',  # URLs
            r'(?:\.)(?:get|post|put|delete|patch)\s*\(\s*(?:"|\'|\`)([a-zA-Z0-9_?&=/\-\#\.]+)',  # AJAX calls
            r'(?:"|\'|\`)(?:[a-zA-Z0-9_\-\.]+\.(?:json|xml|graphql))',  # API resource files
            r'(?:fetch|axios)(?:\s*\.\s*(?:get|post|put|delete|patch))?\s*\(\s*(?:"|\'|\`)(.*?)(?:"|\'|\`)',
            # fetch/axios calls
        ]

        self.secret_patterns = [
            (
            r'(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|app[_-]?secret|appkey|appid|apikey|userid|user[_-]?id|user[_-]?key|auth|password|credentials|mysql|mongo|ftp|database|db|pass|pwd)["\']?\s*(?::|=|==|\s|>|:=|\|)\s*["\']?([a-zA-Z0-9_\-+=/$]{8,64})["\']?',
            "API Key/Secret"),
            (r'(?:"|\'|\`|value=["\'`])([a-zA-Z0-9]{32,45})(?:"|\'|\`)', "Hash/Token"),
            (r'(?i)(?:aws)(?:_|[A-Z0-9])*(?:access|secret|account|key|token|id|credential)', "AWS Key"),
            (r'(?i)(?:github|gh)(?:_|[A-Z0-9])*(?:token|key|secret|pwd|credential|access)', "GitHub Token"),
            (r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', "JWT Token"),
            (r'(?i)(?:firebase|google)(?:_|[A-Z0-9])*(?:key|token|secret|pwd|credential|auth)', "Firebase/Google Key"),
            (r'xox[a-zA-Z]-[a-zA-Z0-9-]+', "Slack Token"),
        ]

        # Stats tracking
        self.stats = {
            'js_urls': 0,
            'downloaded_files': 0,
            'unique_files': 0,
            'extracted_endpoints': 0,
            'potential_secrets': 0,
            'start_time': time.time(),
            'duration': 0,
            'errors': []
        }

        # Results storage
        self.js_urls = set()
        self.downloaded_files = {}
        self.endpoints = set()
        self.secrets = []

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

    def load_urls(self) -> Set[str]:
        """
        Load URLs from the URLs file and filter for JavaScript files.

        Returns:
            Set[str]: Set of JavaScript URLs
        """
        # Try to find URLs file
        if not self.urls_file.exists():
            logger.warning(f"URLs file not found: {self.urls_file}")
            # Try to use subjs to find JS files if we have subdomains
            if self.subdomains_file.exists() and self.check_command('subjs'):
                return self.find_js_with_subjs()
            return set()

        js_urls = set()

        with open(self.urls_file, 'r') as f:
            for line in f:
                url = line.strip()
                if url and '.js' in url:
                    js_urls.add(url)

        logger.info(f"Found {len(js_urls)} JavaScript URLs from urls.txt")

        return js_urls

    def find_js_with_subjs(self) -> Set[str]:
        """
        Find JavaScript files using subjs tool.

        Returns:
            Set[str]: Set of JavaScript URLs
        """
        js_urls = set()

        try:
            logger.info("Using subjs to discover JavaScript files...")

            # Run subjs on subdomains file
            cmd = ['subjs', '-i', str(self.subdomains_file)]

            process = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Process output
            if process.stdout:
                for line in process.stdout.splitlines():
                    if line.strip():
                        js_urls.add(line.strip())

                logger.info(f"subjs found {len(js_urls)} JavaScript URLs")
            else:
                logger.warning("subjs did not find any JavaScript files")

        except subprocess.CalledProcessError as e:
            error_msg = f"subjs failed: {e}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)

        except subprocess.TimeoutExpired:
            error_msg = f"subjs timed out after {self.timeout} seconds"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)

        except Exception as e:
            error_msg = f"Error running subjs: {str(e)}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)

        return js_urls

    def download_js_file(self, url: str) -> Optional[str]:
        """
        Download a JavaScript file.

        Args:
            url: URL of the JavaScript file

        Returns:
            Optional[str]: Path to downloaded file or None if failed
        """
        # Create a unique filename based on URL
        parsed_url = urlparse(url)

        # Use URL path or full URL if no path
        if parsed_url.path:
            filename = parsed_url.path.split('/')[-1]
            if not filename or not filename.endswith('.js'):
                filename = hashlib.md5(url.encode()).hexdigest() + '.js'
        else:
            filename = hashlib.md5(url.encode()).hexdigest() + '.js'

        # Remove invalid characters from filename
        filename = re.sub(r'[^\w\-\.]', '_', filename)

        # Add a random prefix to avoid collisions
        filename = f"{int(time.time())}_{filename}"

        file_path = self.js_files_dir / filename

        try:
            # Make HTTP request with proper headers
            headers = {
                'User-Agent': self.user_agent,
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': f"https://{parsed_url.netloc}/",
                'Connection': 'keep-alive'
            }

            response = requests.get(url, headers=headers, timeout=self.timeout / 10)

            if response.status_code == 200:
                # Check if content is actually JavaScript
                content_type = response.headers.get('Content-Type', '')
                if 'javascript' in content_type or url.endswith('.js'):
                    # Save the content
                    with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(response.text)

                    self.stats['downloaded_files'] += 1
                    logger.debug(f"Downloaded {url} to {file_path}")

                    # Calculate hash to detect duplicates
                    content_hash = hashlib.md5(response.content).hexdigest()

                    return {
                        'url': url,
                        'path': str(file_path),
                        'size': len(response.text),
                        'hash': content_hash
                    }
                else:
                    logger.debug(f"Skipping non-JavaScript content at {url} (Content-Type: {content_type})")
                    return None
            else:
                logger.debug(f"Failed to download {url}: HTTP {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.debug(f"Error downloading {url}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Unexpected error downloading {url}: {e}")
            return None

    def extract_endpoints_from_js(self, js_content: str) -> Set[str]:
        """
        Extract API endpoints and URLs from JavaScript content.

        Args:
            js_content: JavaScript source code

        Returns:
            Set[str]: Set of extracted endpoints
        """
        endpoints = set()

        for pattern in self.endpoint_patterns:
            matches = re.findall(pattern, js_content)
            if matches:
                endpoints.update(matches)

        # Filter and clean endpoints
        filtered_endpoints = set()
        for endpoint in endpoints:
            # Remove quotes and trailing punctuation
            endpoint = endpoint.strip('"\'` ,;)')

            # Skip empty or very short endpoints
            if len(endpoint) < 3:
                continue

            # Skip common false positives
            if endpoint in ['//', '/*', '*/']:
                continue

            filtered_endpoints.add(endpoint)

        return filtered_endpoints

    def extract_secrets_from_js(self, js_content: str) -> List[Dict]:
        """
        Extract potential secrets from JavaScript content.

        Args:
            js_content: JavaScript source code

        Returns:
            List[Dict]: List of potential secrets
        """
        secrets = []

        for pattern, secret_type in self.secret_patterns:
            matches = re.finditer(pattern, js_content)
            for match in matches:
                # Extract the actual secret value
                if len(match.groups()) > 0:
                    secret_value = match.group(1)
                else:
                    secret_value = match.group(0)

                # Skip very short values or obvious false positives
                if len(secret_value) < 8:
                    continue
                if secret_value in ['null', 'undefined', 'localhost', 'password', 'username']:
                    continue

                # Create a context snippet
                line_start = js_content.rfind('\n', 0, match.start()) + 1
                line_end = js_content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(js_content)

                context = js_content[line_start:line_end].strip()

                # Create a secret entry
                secret_entry = {
                    'type': secret_type,
                    'value': secret_value,
                    'context': context,
                    'line': js_content.count('\n', 0, match.start()) + 1
                }

                secrets.append(secret_entry)

        return secrets

    def analyze_js_file(self, file_info: Dict) -> Dict:
        """
        Analyze a JavaScript file to extract endpoints and secrets.

        Args:
            file_info: Information about the JavaScript file

        Returns:
            Dict: Analysis results
        """
        results = {
            'url': file_info['url'],
            'path': file_info['path'],
            'endpoints': [],
            'secrets': []
        }

        try:
            # Read the file content
            with open(file_info['path'], 'r', encoding='utf-8', errors='ignore') as f:
                js_content = f.read()

            # Extract endpoints if enabled
            if self.extract_endpoints:
                endpoints = self.extract_endpoints_from_js(js_content)
                results['endpoints'] = list(endpoints)
                self.endpoints.update(endpoints)
                self.stats['extracted_endpoints'] += len(endpoints)

            # Extract secrets if enabled
            if self.extract_secrets:
                secrets = self.extract_secrets_from_js(js_content)
                results['secrets'] = secrets
                self.secrets.extend(
                    [{**secret, 'file': file_info['path'], 'url': file_info['url']} for secret in secrets])
                self.stats['potential_secrets'] += len(secrets)

        except Exception as e:
            error_msg = f"Error analyzing {file_info['path']}: {str(e)}"
            logger.debug(error_msg)
            self.stats['errors'].append(error_msg)

        return results

    def process_js_url(self, url: str) -> Dict:
        """
        Process a JavaScript URL: download and analyze the file.

        Args:
            url: URL of the JavaScript file

        Returns:
            Dict: Processing results
        """
        results = {
            'url': url,
            'downloaded': False,
            'analyzed': False,
            'file_info': None,
            'analysis': None
        }

        # Download the file if enabled
        if self.download:
            file_info = self.download_js_file(url)
            if file_info:
                results['downloaded'] = True
                results['file_info'] = file_info

                # Analyze the file if enabled
                if self.analyze:
                    analysis = self.analyze_js_file(file_info)
                    results['analyzed'] = True
                    results['analysis'] = analysis

        return results

    def run_scan(self) -> Dict:
        """
        Run JavaScript scanning process.

        Returns:
            Dict: Scan results
        """
        # Load JavaScript URLs
        self.js_urls = self.load_urls()
        if not self.js_urls:
            logger.error("No JavaScript URLs found")
            return {}

        self.stats['js_urls'] = len(self.js_urls)

        # Save JavaScript URLs to file
        with open(self.js_links_file, 'w') as f:
            for url in sorted(self.js_urls):
                f.write(f"{url}\n")

        logger.info(f"Starting JavaScript scanning on {len(self.js_urls)} files")
        start_time = time.time()

        scan_results = {}

        # Process URLs in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {
                executor.submit(self.process_js_url, url): url
                for url in self.js_urls
            }

            for i, future in enumerate(concurrent.futures.as_completed(future_to_url)):
                url = future_to_url[future]
                try:
                    result = future.result()
                    scan_results[url] = result

                    # Log progress
                    if (i + 1) % 10 == 0 or (i + 1) == len(self.js_urls):
                        progress = ((i + 1) / len(self.js_urls)) * 100
                        logger.info(f"Progress: {progress:.1f}% ({i + 1}/{len(self.js_urls)})")

                except Exception as e:
                    logger.error(f"Error processing {url}: {e}")

        # Update stats
        self.stats['duration'] = time.time() - start_time

        # Check for duplicate files
        unique_hashes = set()
        for url, result in scan_results.items():
            if result.get('file_info') and result['file_info'].get('hash'):
                unique_hashes.add(result['file_info']['hash'])

        self.stats['unique_files'] = len(unique_hashes)

        # Save results
        self.save_results()

        logger.info(f"JavaScript scanning completed in {self.stats['duration']:.2f} seconds")
        logger.info(
            f"Downloaded {self.stats['downloaded_files']} JavaScript files ({self.stats['unique_files']} unique)")
        if self.extract_endpoints:
            logger.info(f"Extracted {self.stats['extracted_endpoints']} potential endpoints")
        if self.extract_secrets:
            logger.info(f"Found {self.stats['potential_secrets']} potential secrets")

        return scan_results

    def save_results(self) -> None:
        """Save scan results to output files."""
        # Save endpoints if any
        if self.endpoints:
            with open(self.endpoints_file, 'w') as f:
                for endpoint in sorted(self.endpoints):
                    f.write(f"{endpoint}\n")

            logger.info(f"Endpoints saved to {self.endpoints_file}")

        # Save secrets if any
        if self.secrets:
            with open(self.secrets_file, 'w') as f:
                json.dump(self.secrets, f, indent=4)

            logger.info(f"Potential secrets saved to {self.secrets_file}")

        # Save metadata
        metadata = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'features_enabled': {
                'download': self.download,
                'analyze': self.analyze,
                'extract_endpoints': self.extract_endpoints,
                'extract_secrets': self.extract_secrets
            }
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)

        logger.info(f"Metadata saved to {self.metadata_file}")

        # Generate summary
        self.generate_summary()

    def generate_summary(self) -> None:
        """Generate a summary of the JavaScript scanning results."""
        with open(self.summary_file, 'w') as f:
            f.write(f"JavaScript Scanning Summary for {self.domain}\n")
            f.write(f"=======================================\n\n")
            f.write(f"Scan completed: {datetime.now().isoformat()}\n")
            f.write(f"Scan duration: {self.stats['duration']:.2f} seconds\n\n")

            f.write("Files Summary\n")
            f.write("------------\n")
            f.write(f"JavaScript URLs found: {self.stats['js_urls']}\n")
            f.write(f"Files downloaded: {self.stats['downloaded_files']}\n")
            f.write(f"Unique files (by content): {self.stats['unique_files']}\n\n")

            if self.extract_endpoints:
                f.write("Endpoints Summary\n")
                f.write("----------------\n")
                f.write(f"Endpoints extracted: {self.stats['extracted_endpoints']}\n")

                # List top domains in endpoints
                domains_in_endpoints = {}
                for endpoint in self.endpoints:
                    if endpoint.startswith('http'):
                        domain = urlparse(endpoint).netloc
                        domains_in_endpoints[domain] = domains_in_endpoints.get(domain, 0) + 1

                if domains_in_endpoints:
                    f.write("\nTop domains referenced in endpoints:\n")
                    for domain, count in sorted(domains_in_endpoints.items(), key=lambda x: x[1], reverse=True)[:10]:
                        f.write(f"- {domain}: {count}\n")

                f.write("\n")

            if self.extract_secrets:
                f.write("Secrets Summary\n")
                f.write("--------------\n")
                f.write(f"Potential secrets found: {self.stats['potential_secrets']}\n")

                # Group secrets by type
                secret_types = {}
                for secret in self.secrets:
                    secret_type = secret['type']
                    secret_types[secret_type] = secret_types.get(secret_type, 0) + 1

                if secret_types:
                    f.write("\nSecrets by type:\n")
                    for secret_type, count in sorted(secret_types.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"- {secret_type}: {count}\n")

                f.write("\n")

            # If there were errors, mention them
            if self.stats['errors']:
                f.write("Errors\n")
                f.write("------\n")
                f.write(f"Encountered {len(self.stats['errors'])} errors during scanning\n")
                f.write("Check logs for details\n\n")

        logger.info(f"Summary saved to {self.summary_file}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="JavaScript scanning module for reconX",
        epilog="Example: python3 js_scan.py example.com --threads 20"
    )

    parser.add_argument('domain', help="Target domain for JavaScript scanning")
    parser.add_argument('-o', '--output', help="Custom output directory")
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help="Number of concurrent operations (default: 10)")
    parser.add_argument('--timeout', type=int, default=600,
                        help="Timeout in seconds for operations (default: 600)")

    # Feature selection
    feature_group = parser.add_argument_group('Feature Selection')
    feature_group.add_argument('--no-download', action='store_true',
                               help="Disable downloading of JavaScript files")
    feature_group.add_argument('--no-analyze', action='store_true',
                               help="Disable analysis of JavaScript files")
    feature_group.add_argument('--no-endpoints', action='store_true',
                               help="Disable endpoint extraction")
    feature_group.add_argument('--no-secrets', action='store_true',
                               help="Disable secret extraction")

    # Additional options
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument('--user-agent',
                            help="Custom User-Agent for HTTP requests")
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
        # Create and run the JavaScript scanner
        scanner = JSScanner(
            domain=args.domain,
            output_dir=output_dir,
            threads=args.threads,
            timeout=args.timeout,
            download=not args.no_download,
            analyze=not args.no_analyze,
            extract_endpoints=not args.no_endpoints,
            extract_secrets=not args.no_secrets,
            user_agent=args.user_agent
        )

        results = scanner.run_scan()
        return 0 if results else 1

    except KeyboardInterrupt:
        logger.info("JavaScript scanning interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())