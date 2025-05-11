#!/usr/bin/env python3
"""
urls.py - URL enumeration module for reconX

This module discovers URLs associated with target subdomains using various
tools like waybackurls, gau, hakrawler, and more. It collects historical
and current endpoints to provide a comprehensive view of the target's attack surface.

Author: @0xk4b1r
License: MIT
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Union
import time
import json
import concurrent.futures
from datetime import datetime
import re
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('urls_enum')


class URLEnumerator:
    """Class for performing URL enumeration on discovered subdomains."""

    def __init__(self, domain: str, output_dir: Optional[Path] = None,
                 threads: int = 10, timeout: int = 600,
                 tools: Optional[List[str]] = None,
                 filter_extensions: Optional[List[str]] = None,
                 include_js: bool = True):
        """
        Initialize the URL enumerator.

        Args:
            domain: Target domain
            output_dir: Directory to store results (default: ./test/output/<domain>)
            threads: Number of threads for concurrent operations
            timeout: Timeout in seconds for the enumeration operations
            tools: List of tools to use (default: all available)
            filter_extensions: List of file extensions to filter for
            include_js: Whether to include JavaScript files
        """
        self.domain = domain
        
        # Handle output directory properly
        if output_dir:
            # If output_dir is provided, use it and append domain
            self.output_dir = output_dir / domain
        else:
            # Otherwise use the default
            self.output_dir = Path('./test/output') / domain
            
        self.threads = threads
        self.timeout = timeout
        self.tools = tools or ['waybackurls', 'gau', 'hakrawler']
        self.filter_extensions = filter_extensions
        self.include_js = include_js

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Log the actual output directory being used
        logger.info(f"Using output directory: {self.output_dir}")

        # Set up input and output files
        self.subdomains_file = self.output_dir / 'subdomains.txt'
        self.urls_file = self.output_dir / 'urls.txt'
        self.js_urls_file = self.output_dir / 'js_urls.txt'
        self.metadata_file = self.output_dir / 'urls_enum_metadata.json'

        # Dictionary to store URLs by tool
        self.tool_results = {}

        # Set to store all unique URLs
        self.all_urls = set()

        # Set to store JS URLs
        self.js_urls = set()

        # Stats tracking
        self.stats = {
            'total_subdomains': 0,
            'processed_subdomains': 0,
            'total_urls': 0,
            'js_urls': 0,
            'start_time': time.time(),
            'duration': 0,
            'tool_stats': {},
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

    def get_available_tools(self) -> List[str]:
        """
        Get a list of available URL enumeration tools.

        Returns:
            List[str]: List of available tools
        """
        available_tools = []
        for tool in self.tools:
            if self.check_command(tool):
                available_tools.append(tool)
            else:
                logger.warning(f"Tool {tool} not found in PATH")

        return available_tools

    def load_subdomains(self) -> List[str]:
        """
        Load subdomains from the subdomain file.

        Returns:
            List[str]: List of subdomains
        """
        if not self.subdomains_file.exists():
            logger.error(f"Subdomains file not found: {self.subdomains_file}")
            logger.error("Make sure subdomain enumeration was run first and check your output path")
            return []

        try:
            with open(self.subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]

            logger.info(f"Loaded {len(subdomains)} subdomains for URL enumeration")
            self.stats['total_subdomains'] = len(subdomains)
            
            # If no subdomains found in the file
            if not subdomains:
                logger.warning(f"Subdomain file exists but contains no data: {self.subdomains_file}")
                
            return subdomains
        except Exception as e:
            logger.error(f"Error loading subdomains file: {e}")
            return []

    def run_waybackurls(self, subdomain: str) -> Set[str]:
        """
        Run waybackurls on a subdomain.

        Args:
            subdomain: The subdomain to scan

        Returns:
            Set[str]: Set of discovered URLs
        """
        urls = set()

        try:
            cmd = ['waybackurls', subdomain]

            logger.debug(f"Running: {' '.join(cmd)}")

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
                        urls.add(line.strip())

                # Update tool stats
                self.stats['tool_stats'].setdefault('waybackurls', {
                    'total_urls': 0,
                    'subdomains_processed': 0
                })
                self.stats['tool_stats']['waybackurls']['total_urls'] += len(urls)
                self.stats['tool_stats']['waybackurls']['subdomains_processed'] += 1

                logger.info(f"waybackurls found {len(urls)} URLs for {subdomain}")

        except subprocess.CalledProcessError as e:
            error_msg = f"waybackurls failed for {subdomain}: {e}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = f"waybackurls timed out for {subdomain} after {self.timeout} seconds"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error running waybackurls on {subdomain}: {str(e)}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)

        return urls

    def run_gau(self, subdomain: str) -> Set[str]:
        """
        Run gau (getallurls) on a subdomain.

        Args:
            subdomain: The subdomain to scan

        Returns:
            Set[str]: Set of discovered URLs
        """
        urls = set()

        try:
            cmd = ['gau', subdomain]

            logger.debug(f"Running: {' '.join(cmd)}")

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
                        urls.add(line.strip())

                # Update tool stats
                self.stats['tool_stats'].setdefault('gau', {
                    'total_urls': 0,
                    'subdomains_processed': 0
                })
                self.stats['tool_stats']['gau']['total_urls'] += len(urls)
                self.stats['tool_stats']['gau']['subdomains_processed'] += 1

                logger.info(f"gau found {len(urls)} URLs for {subdomain}")

        except subprocess.CalledProcessError as e:
            error_msg = f"gau failed for {subdomain}: {e}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = f"gau timed out for {subdomain} after {self.timeout} seconds"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error running gau on {subdomain}: {str(e)}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)

        return urls

    def run_hakrawler(self, subdomain: str) -> Set[str]:
        """
        Run hakrawler on a subdomain.

        Args:
            subdomain: The subdomain to scan

        Returns:
            Set[str]: Set of discovered URLs
        """
        urls = set()

        try:
            # Ensure we use http:// or https:// prefix
            if not (subdomain.startswith('http://') or subdomain.startswith('https://')):
                subdomain = f"http://{subdomain}"

            cmd = ['hakrawler', '-url', subdomain, '-depth', '2', '-plain']

            logger.debug(f"Running: {' '.join(cmd)}")

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
                        urls.add(line.strip())

                # Update tool stats
                self.stats['tool_stats'].setdefault('hakrawler', {
                    'total_urls': 0,
                    'subdomains_processed': 0
                })
                self.stats['tool_stats']['hakrawler']['total_urls'] += len(urls)
                self.stats['tool_stats']['hakrawler']['subdomains_processed'] += 1

                logger.info(f"hakrawler found {len(urls)} URLs for {subdomain}")

        except subprocess.CalledProcessError as e:
            error_msg = f"hakrawler failed for {subdomain}: {e}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = f"hakrawler timed out for {subdomain} after {self.timeout} seconds"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error running hakrawler on {subdomain}: {str(e)}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)

        return urls

    def process_subdomain(self, subdomain: str) -> Dict[str, Set[str]]:
        """
        Process a subdomain with all available tools.

        Args:
            subdomain: The subdomain to process

        Returns:
            Dict[str, Set[str]]: Dictionary mapping tool names to sets of URLs
        """
        results = {}
        available_tools = self.get_available_tools()

        if 'waybackurls' in available_tools:
            results['waybackurls'] = self.run_waybackurls(subdomain)

        if 'gau' in available_tools:
            results['gau'] = self.run_gau(subdomain)

        if 'hakrawler' in available_tools:
            results['hakrawler'] = self.run_hakrawler(subdomain)

        # Update processed count
        self.stats['processed_subdomains'] += 1

        # Log progress
        progress = (self.stats['processed_subdomains'] / self.stats['total_subdomains']) * 100
        logger.info(
            f"Progress: {progress:.1f}% ({self.stats['processed_subdomains']}/{self.stats['total_subdomains']})")

        return results

    def filter_urls(self, urls: Set[str]) -> Set[str]:
        """
        Filter URLs based on configured criteria.

        Args:
            urls: Set of URLs to filter

        Returns:
            Set[str]: Set of filtered URLs
        """
        filtered_urls = set()

        for url in urls:
            # Basic URL validation
            if not url or not isinstance(url, str):
                continue

            # Skip URLs that don't contain our domain
            if self.domain not in url:
                continue

            # Apply extension filtering if specified
            if self.filter_extensions:
                _, ext = os.path.splitext(urlparse(url).path)
                if ext and ext[1:] in self.filter_extensions:
                    filtered_urls.add(url)
            else:
                filtered_urls.add(url)

        return filtered_urls

    def categorize_urls(self, urls: Set[str]) -> Dict[str, Set[str]]:
        """
        Categorize URLs by type.

        Args:
            urls: Set of URLs to categorize

        Returns:
            Dict[str, Set[str]]: Dictionary mapping categories to sets of URLs
        """
        categories = {
            'js': set(),
            'api': set(),
            'static': set(),
            'others': set()
        }

        js_pattern = r'\.js(\?|$)'
        api_pattern = r'(/api/|/graphql|/v\d+/)'
        static_extensions = ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf']

        for url in urls:
            if re.search(js_pattern, url, re.IGNORECASE):
                categories['js'].add(url)
            elif re.search(api_pattern, url, re.IGNORECASE):
                categories['api'].add(url)
            elif any(ext in url.lower() for ext in static_extensions):
                categories['static'].add(url)
            else:
                categories['others'].add(url)

        return categories

    def run_enumeration(self) -> Set[str]:
        """
        Run full URL enumeration on all subdomains.

        Returns:
            Set[str]: Set of all discovered URLs
        """
        # Load subdomains
        subdomains = self.load_subdomains()
        if not subdomains:
            logger.error("No subdomains found for URL enumeration")
            return set()

        logger.info(f"Starting URL enumeration on {len(subdomains)} subdomains")
        start_time = time.time()

        # Process each subdomain with multiple tools
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self.process_subdomain, subdomain): subdomain
                for subdomain in subdomains
            }

            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    results = future.result()

                    # Store results by tool
                    for tool, tool_urls in results.items():
                        self.tool_results.setdefault(tool, set()).update(tool_urls)

                        # Update global URL sets
                        self.all_urls.update(tool_urls)

                        # Extract JS URLs
                        if self.include_js:
                            js_urls = {url for url in tool_urls if url.endswith('.js')}
                            self.js_urls.update(js_urls)

                except Exception as e:
                    logger.error(f"Error processing results for {subdomain}: {e}")

        # Update stats
        self.stats['duration'] = time.time() - start_time
        self.stats['total_urls'] = len(self.all_urls)
        self.stats['js_urls'] = len(self.js_urls)

        # Save results
        self.save_results()

        # Log summary
        logger.info(f"URL enumeration completed in {self.stats['duration']:.2f} seconds")
        logger.info(f"Found {self.stats['total_urls']} unique URLs")
        if self.include_js:
            logger.info(f"Found {self.stats['js_urls']} JavaScript URLs")

        return self.all_urls

    def save_results(self) -> None:
        """Save enumeration results to output files."""
        # Save all URLs
        with open(self.urls_file, 'w') as f:
            for url in sorted(self.all_urls):
                f.write(f"{url}\n")

        # Save JS URLs if requested
        if self.include_js and self.js_urls:
            with open(self.js_urls_file, 'w') as f:
                for url in sorted(self.js_urls):
                    f.write(f"{url}\n")

        # Save tool-specific results
        for tool, urls in self.tool_results.items():
            tool_file = self.output_dir / f"{tool}_urls.txt"
            with open(tool_file, 'w') as f:
                for url in sorted(urls):
                    f.write(f"{url}\n")

        # Save metadata
        metadata = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'tools_used': list(self.tool_results.keys()),
            'categories': {
                category: len(urls)
                for category, urls in self.categorize_urls(self.all_urls).items()
            }
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)

        logger.info(f"Results saved to {self.urls_file}")
        if self.include_js:
            logger.info(f"JavaScript URLs saved to {self.js_urls_file}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="URL enumeration module for reconX",
        epilog="Example: python3 urls.py example.com --tools waybackurls,gau"
    )

    parser.add_argument('domain', help="Target domain for URL enumeration")
    parser.add_argument('-o', '--output', help="Custom output directory")
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help="Number of threads for concurrent operations")
    parser.add_argument('--timeout', type=int, default=600,
                        help="Timeout in seconds for each enumeration operation")
    parser.add_argument('--tools', help="Comma-separated list of tools to use")
    parser.add_argument('--filter', help="Comma-separated list of file extensions to filter for")
    parser.add_argument('--no-js', action='store_true',
                        help="Don't extract JavaScript URLs separately")
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
        logger.debug(f"Using custom output directory: {output_dir}")

    # Parse tools list if specified
    tools = None
    if args.tools:
        tools = [t.strip() for t in args.tools.split(',')]
        logger.debug(f"Using specified tools: {tools}")

    # Parse filter extensions if specified
    filter_extensions = None
    if args.filter:
        filter_extensions = [ext.strip() for ext in args.filter.split(',')]
        logger.debug(f"Filtering for extensions: {filter_extensions}")

    try:
        # Create and run the URL enumerator
        enumerator = URLEnumerator(
            domain=args.domain,
            output_dir=output_dir,
            threads=args.threads,
            timeout=args.timeout,
            tools=tools,
            filter_extensions=filter_extensions,
            include_js=not args.no_js
        )

        # Check if the subdomains file exists before proceeding
        if not enumerator.subdomains_file.exists():
            logger.error(f"Subdomains file not found: {enumerator.subdomains_file}")
            logger.error("Run subdomain enumeration first or check the output directory path")
            return 1

        urls = enumerator.run_enumeration()
        
        # Add more verbose output about where files were saved
        logger.info(f"URLs saved to: {enumerator.urls_file}")
        if enumerator.include_js:
            logger.info(f"JavaScript URLs saved to: {enumerator.js_urls_file}")
        logger.info(f"Metadata saved to: {enumerator.metadata_file}")
        
        return 0 if urls else 1

    except KeyboardInterrupt:
        logger.info("URL enumeration interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())