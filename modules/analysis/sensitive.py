#!/usr/bin/env python3
"""
sensitive.py - Sensitive information enumeration module for reconX

This module looks for exposed sensitive information, files, and directories
that might contain valuable data or indicate security issues. It can discover
exposed git repositories, environment files, backup files, and other
potentially sensitive information.

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
from datetime import datetime
import re
import requests
from urllib.parse import urlparse, urljoin
import tempfile
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('sensitive_info_enum')


class SensitiveInfoEnumerator:
    """Class for enumerating sensitive information."""

    def __init__(self, domain: str, output_dir: Optional[Path] = None,
                 threads: int = 10, timeout: int = 600,
                 scan_git: bool = True, scan_env_files: bool = True,
                 scan_backups: bool = True, scan_config_files: bool = True,
                 scan_exposed_panels: bool = True,
                 download_files: bool = True,
                 user_agent: Optional[str] = None):
        """
        Initialize the sensitive information enumerator.

        Args:
            domain: Target domain
            output_dir: Directory to store results (default: ./test/output/<domain>)
            threads: Number of concurrent operations
            timeout: Timeout in seconds for operations
            scan_git: Whether to scan for exposed git repositories
            scan_env_files: Whether to scan for exposed environment files
            scan_backups: Whether to scan for backup files
            scan_config_files: Whether to scan for config files
            scan_exposed_panels: Whether to scan for exposed admin panels
            download_files: Whether to download found files
            user_agent: Custom User-Agent for requests
        """
        self.domain = domain
        self.output_dir = output_dir or Path('./test/output') / domain
        self.threads = threads
        self.timeout = timeout
        self.scan_git = scan_git
        self.scan_env_files = scan_env_files
        self.scan_backups = scan_backups
        self.scan_config_files = scan_config_files
        self.scan_exposed_panels = scan_exposed_panels
        self.download_files = download_files
        self.user_agent = user_agent or "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up input and output files/directories
        self.subdomains_file = self.output_dir / 'subdomains.txt'
        self.urls_file = self.output_dir / 'urls.txt'

        self.sensitive_dir = self.output_dir / 'sensitive'
        self.sensitive_files_dir = self.sensitive_dir / 'files'
        self.results_file = self.sensitive_dir / 'sensitive_results.json'
        self.metadata_file = self.sensitive_dir / 'sensitive_metadata.json'
        self.summary_file = self.sensitive_dir / 'sensitive_summary.txt'

        # Create necessary directories
        self.sensitive_dir.mkdir(exist_ok=True)
        if self.download_files:
            self.sensitive_files_dir.mkdir(exist_ok=True)

        # Define patterns for sensitive files and directories
        self.sensitive_patterns = self._get_sensitive_patterns()

        # Stats tracking
        self.stats = {
            'total_subdomains': 0,
            'processed_subdomains': 0,
            'sensitive_urls_found': 0,
            'downloaded_files': 0,
            'start_time': time.time(),
            'duration': 0,
            'errors': []
        }

        # Results storage
        self.sensitive_urls = set()
        self.findings = []
        self.downloaded_files = {}

    def _get_sensitive_patterns(self) -> Dict[str, List[str]]:
        """
        Get patterns for sensitive files and directories.

        Returns:
            Dict[str, List[str]]: Dictionary of pattern categories and patterns
        """
        patterns = {
            'git_repository': [
                '.git/HEAD',
                '.git/config',
                '.git/index',
                '.git/logs/HEAD'
            ],
            'environment_files': [
                '.env',
                '.env.local',
                '.env.development',
                '.env.production',
                '.env.backup',
                'env.js',
                'environment.js',
                'settings.env',
                'local.env',
                'config.env'
            ],
            'backup_files': [
                'backup.zip',
                'backup.tar.gz',
                'backup.sql',
                'backup.bak',
                'backup.old',
                '*.bak',
                '*.backup',
                '*.old',
                '*.temp',
                '*.tmp',
                '*.swp',
                '.DS_Store'
            ],
            'config_files': [
                'config.php',
                'config.json',
                'config.xml',
                'config.js',
                'config.ini',
                'configuration.php',
                'settings.php',
                'settings.json',
                'settings.xml',
                'database.php',
                'db.php',
                'db.json',
                'wp-config.php',
                'wp-config.bak',
                'web.config',
                'robots.txt',
                'composer.json',
                'package.json'
            ],
            'exposed_panels': [
                'admin/',
                'administrator/',
                'login/',
                'admin/login',
                'wp-admin/',
                'wp-login.php',
                'phpmyadmin/',
                'adminer.php',
                'admin.php',
                'panel/',
                'cpanel/',
                'dashboard/',
                'console/'
            ]
        }

        return patterns

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
                # Also try https
                normalized_subdomains.append(f"https://{subdomain}")
            else:
                normalized_subdomains.append(subdomain)

        logger.info(f"Loaded {len(normalized_subdomains)} URLs for sensitive information enumeration")
        self.stats['total_subdomains'] = len(normalized_subdomains)
        return normalized_subdomains

    def check_url(self, url: str, path: str) -> Optional[Dict]:
        """
        Check if a URL + path exists and contains sensitive information.

        Args:
            url: Base URL
            path: Path to check

        Returns:
            Optional[Dict]: Finding information if sensitive info is found
        """
        # Create full URL
        full_url = urljoin(url, path)

        try:
            # Make HTTP request with proper headers
            headers = {
                'User-Agent': self.user_agent,
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive'
            }

            response = requests.get(full_url, headers=headers, timeout=10, allow_redirects=False)

            # Check for positive match
            if response.status_code == 200:
                # Create finding
                finding = {
                    'url': full_url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                    'path': path,
                    'category': self._get_path_category(path),
                    'timestamp': datetime.now().isoformat()
                }

                # Check file content for additional confirmation
                if self._is_valid_content(path, response):
                    logger.info(f"Found sensitive URL: {full_url}")

                    # Download the file if enabled
                    if self.download_files:
                        file_path = self._download_file(full_url, response.content)
                        if file_path:
                            finding['downloaded_path'] = str(file_path)

                    return finding

            return None

        except requests.RequestException as e:
            logger.debug(f"Error checking {full_url}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Unexpected error checking {full_url}: {e}")
            return None

    def _get_path_category(self, path: str) -> str:
        """
        Get the category of a path based on defined patterns.

        Args:
            path: Path to categorize

        Returns:
            str: Category name
        """
        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                if pattern == path or (pattern.startswith('*') and path.endswith(pattern[1:])):
                    return category
        return 'unknown'

    def _is_valid_content(self, path: str, response: requests.Response) -> bool:
        """
        Check if the response content is valid for the path.

        Args:
            path: Path being checked
            response: HTTP response

        Returns:
            bool: True if content is valid, False otherwise
        """
        content = response.content
        content_type = response.headers.get('Content-Type', '')

        # Git repository files
        if '.git/' in path:
            # Git HEAD file should contain 'ref:'
            if path.endswith('HEAD') and b'ref:' in content:
                return True
            # Git config should contain [core]
            elif path.endswith('config') and (b'[core]' in content or b'repositoryformatversion' in content):
                return True
            # Git index file should start with 'DIRC'
            elif path.endswith('index') and content[:4] == b'DIRC':
                return True
            return False

        # Environment files
        elif '.env' in path or path.endswith('env.js'):
            return b'=' in content or b':' in content

        # Config files
        elif 'config' in path or 'settings' in path:
            return (b'{' in content and b'}' in content) or b'=' in content or b'<?php' in content

        # Any content for other files, but check minimum size
        return len(content) > 5

    def _download_file(self, url: str, content: bytes) -> Optional[Path]:
        """
        Download and save a file.

        Args:
            url: URL of the file
            content: File content

        Returns:
            Optional[Path]: Path to downloaded file or None if failed
        """
        try:
            # Parse URL to get path components
            parsed_url = urlparse(url)
            path = parsed_url.path

            # Create a clean filename
            if path and path != '/':
                filename = path.split('/')[-1]
                if not filename:
                    filename = path.replace('/', '_').lstrip('_')
            else:
                filename = f"{parsed_url.netloc}_index.html"

            # Remove invalid characters
            filename = re.sub(r'[^\w\-\.]', '_', filename)

            # Add domain prefix to avoid collisions
            domain_prefix = parsed_url.netloc.replace('.', '_')
            filename = f"{domain_prefix}_{filename}"

            file_path = self.sensitive_files_dir / filename

            # Save the content
            with open(file_path, 'wb') as f:
                f.write(content)

            self.stats['downloaded_files'] += 1
            logger.debug(f"Downloaded {url} to {file_path}")

            return file_path

        except Exception as e:
            logger.debug(f"Error downloading {url}: {e}")
            return None

    def scan_subdomain(self, url: str) -> List[Dict]:
        """
        Scan a subdomain for sensitive information.

        Args:
            url: Subdomain URL

        Returns:
            List[Dict]: List of findings for this subdomain
        """
        findings = []

        # Build list of paths to check
        paths_to_check = []

        if self.scan_git:
            paths_to_check.extend(self.sensitive_patterns['git_repository'])

        if self.scan_env_files:
            paths_to_check.extend(self.sensitive_patterns['environment_files'])

        if self.scan_backups:
            paths_to_check.extend(self.sensitive_patterns['backup_files'])

        if self.scan_config_files:
            paths_to_check.extend(self.sensitive_patterns['config_files'])

        if self.scan_exposed_panels:
            paths_to_check.extend(self.sensitive_patterns['exposed_panels'])

        # Check each path
        for path in paths_to_check:
            # Skip wildcard patterns as they can't be directly requested
            if '*' in path:
                continue

            finding = self.check_url(url, path)
            if finding:
                findings.append(finding)
                self.sensitive_urls.add(finding['url'])
                self.stats['sensitive_urls_found'] += 1

        # Update processed count
        self.stats['processed_subdomains'] += 1

        # Log progress periodically
        if self.stats['processed_subdomains'] % 5 == 0:
            progress = (self.stats['processed_subdomains'] / self.stats['total_subdomains']) * 100
            logger.info(
                f"Progress: {progress:.1f}% ({self.stats['processed_subdomains']}/{self.stats['total_subdomains']})")

        return findings

    def check_httpx_available(self) -> bool:
        """
        Check if httpx tool is available.

        Returns:
            bool: True if httpx is available, False otherwise
        """
        return self.check_command('httpx')

    def check_urls_with_httpx(self, urls: List[str]) -> List[str]:
        """
        Check URLs with httpx for faster processing.

        Args:
            urls: List of URLs to check

        Returns:
            List[str]: List of URLs that responded
        """
        if not self.check_httpx_available():
            logger.warning("httpx not found, skipping batch URL verification")
            return urls

        logger.info("Using httpx to verify URLs...")
        active_urls = []

        try:
            # Create a temporary file with URLs
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file_path = temp_file.name
                for url in urls:
                    temp_file.write(f"{url}\n")

            # Run httpx
            cmd = [
                'httpx',
                '-silent',
                '-l', temp_file_path,
                '-timeout', '5',
                '-status-code',
                '-no-color'
            ]

            process = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Process output
            for line in process.stdout.splitlines():
                if line.strip():
                    # httpx output format: url [status_code]
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].startswith('[') and parts[1].endswith(']'):
                        url = parts[0]
                        status_code = parts[1].strip('[]')
                        if status_code.startswith('2') or status_code.startswith('3'):
                            active_urls.append(url)

            logger.info(f"httpx found {len(active_urls)} active URLs out of {len(urls)}")

        except subprocess.CalledProcessError as e:
            logger.error(f"httpx failed: {e}")
            return urls
        except Exception as e:
            logger.error(f"Error running httpx: {e}")
            return urls
        finally:
            # Clean up the temporary file
            try:
                os.unlink(temp_file_path)
            except Exception:
                pass

        return active_urls if active_urls else urls

    def run_enumeration(self) -> List[Dict]:
        """
        Run sensitive information enumeration.

        Returns:
            List[Dict]: List of findings
        """
        # Load subdomains
        urls = self.load_subdomains()
        if not urls:
            logger.error("No subdomains found for enumeration")
            return []

        # Check URLs with httpx first to filter out inactive ones
        active_urls = self.check_urls_with_httpx(urls)

        logger.info(f"Starting sensitive information enumeration on {len(active_urls)} URLs")
        start_time = time.time()

        # Process each URL in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {
                executor.submit(self.scan_subdomain, url): url
                for url in active_urls
            }

            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    findings = future.result()
                    self.findings.extend(findings)
                except Exception as e:
                    logger.error(f"Error processing {url}: {e}")
                    self.stats['errors'].append(f"Error processing {url}: {str(e)}")

        # Update stats
        self.stats['duration'] = time.time() - start_time

        # Save results
        self.save_results()

        logger.info(f"Sensitive information enumeration completed in {self.stats['duration']:.2f} seconds")
        logger.info(f"Found {self.stats['sensitive_urls_found']} sensitive URLs")
        if self.download_files:
            logger.info(f"Downloaded {self.stats['downloaded_files']} files")

        return self.findings

    def save_results(self) -> None:
        """Save enumeration results to output files."""
        # Save findings as JSON
        with open(self.results_file, 'w') as f:
            json.dump(self.findings, f, indent=4)

        logger.info(f"Results saved to {self.results_file}")

        # Save metadata
        metadata = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'enabled_features': {
                'scan_git': self.scan_git,
                'scan_env_files': self.scan_env_files,
                'scan_backups': self.scan_backups,
                'scan_config_files': self.scan_config_files,
                'scan_exposed_panels': self.scan_exposed_panels,
                'download_files': self.download_files
            }
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)

        logger.info(f"Metadata saved to {self.metadata_file}")

        # Generate summary
        self.generate_summary()

    def generate_summary(self) -> None:
        """Generate a summary of the sensitive information findings."""
        with open(self.summary_file, 'w') as f:
            f.write(f"Sensitive Information Enumeration Summary for {self.domain}\n")
            f.write(f"=================================================\n\n")
            f.write(f"Scan completed: {datetime.now().isoformat()}\n")
            f.write(f"Scan duration: {self.stats['duration']:.2f} seconds\n\n")

            f.write("Findings Summary\n")
            f.write("---------------\n")
            f.write(f"URLs scanned: {self.stats['processed_subdomains']}\n")
            f.write(f"Sensitive URLs found: {self.stats['sensitive_urls_found']}\n")
            if self.download_files:
                f.write(f"Files downloaded: {self.stats['downloaded_files']}\n")
            f.write("\n")

            # Group findings by category
            findings_by_category = {}
            for finding in self.findings:
                category = finding['category']
                findings_by_category.setdefault(category, []).append(finding)

            # Write findings by category
            for category, category_findings in findings_by_category.items():
                f.write(f"{category.replace('_', ' ').title()} ({len(category_findings)})\n")
                f.write(f"{'-' * (len(category) + 2 + len(str(len(category_findings))))}\n")

                for finding in category_findings[:10]:  # Limit to top 10 per category
                    f.write(f"- {finding['url']}\n")

                if len(category_findings) > 10:
                    f.write(f"- ... and {len(category_findings) - 10} more\n")

                f.write("\n")

            # If there were errors, mention them
            if self.stats['errors']:
                f.write("Errors\n")
                f.write("------\n")
                f.write(f"Encountered {len(self.stats['errors'])} errors during enumeration\n")
                f.write("Check logs for details\n\n")

        logger.info(f"Summary saved to {self.summary_file}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Sensitive information enumeration module for reconX",
        epilog="Example: python3 sensitive.py example.com --threads 20"
    )

    parser.add_argument('domain', help="Target domain for sensitive information enumeration")
    parser.add_argument('-o', '--output', help="Custom output directory")
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help="Number of concurrent operations (default: 10)")
    parser.add_argument('--timeout', type=int, default=600,
                        help="Timeout in seconds for operations (default: 600)")

    # Feature selection
    feature_group = parser.add_argument_group('Feature Selection')
    feature_group.add_argument('--no-git', action='store_true',
                               help="Disable scanning for exposed git repositories")
    feature_group.add_argument('--no-env', action='store_true',
                               help="Disable scanning for environment files")
    feature_group.add_argument('--no-backups', action='store_true',
                               help="Disable scanning for backup files")
    feature_group.add_argument('--no-config', action='store_true',
                               help="Disable scanning for config files")
    feature_group.add_argument('--no-panels', action='store_true',
                               help="Disable scanning for exposed admin panels")
    feature_group.add_argument('--no-download', action='store_true',
                               help="Disable downloading of found files")

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
        # Create and run the sensitive information enumerator
        enumerator = SensitiveInfoEnumerator(
            domain=args.domain,
            output_dir=output_dir,
            threads=args.threads,
            timeout=args.timeout,
            scan_git=not args.no_git,
            scan_env_files=not args.no_env,
            scan_backups=not args.no_backups,
            scan_config_files=not args.no_config,
            scan_exposed_panels=not args.no_panels,
            download_files=not args.no_download,
            user_agent=args.user_agent
        )

        findings = enumerator.run_enumeration()
        return 0 if findings else 1

    except KeyboardInterrupt:
        logger.info("Sensitive information enumeration interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())