#!/usr/bin/env python3
"""
reconX - A comprehensive reconnaissance framework
Author: @0xk4b1r
License: MIT
"""

import os
import sys
import subprocess
import argparse
import logging
import time
from pathlib import Path
from typing import List, Optional

# Configuration paths
RECONX_MODULES = Path('./modules/').resolve()
RECONX_OUTPUT_PATH = Path('./test/output/').resolve()
VERSION = "1.0.0"


def setup_logger() -> logging.Logger:
    """Configure and return a logger instance for reconX."""
    logger = logging.getLogger("reconX")
    logger.setLevel(logging.INFO)

    # Create console handler with formatting
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


logger = setup_logger()


def display_banner() -> None:
    """Display the reconX banner."""
    print('''
    __________
    \______   \ ____   ____  ____   __ _____     ____   ____
    |       _// __ \_/ ___\/  _ \ /    \__  \   / ___\_/ __  \\
    |    |   \  ___/\  \__(  <_> )   |  \/ __ \_/ /_/  >  ___/
    |____|_  /\___  >\___  >____/|___|  (____  /\___  / \___  >
            \/     \/     \/           \/     \//_____/      \/
                reconX v{} by @0xk4b1r - Comprehensive Reconnaissance Framework
    '''.format(VERSION))


def ensure_directories_exist(output_path: Optional[Path] = None) -> Path:
    """
    Ensure that necessary directories exist.

    Args:
        output_path: Optional custom output path

    Returns:
        Path: The actual output path being used
    """
    # Use custom output path if provided
    actual_output_path = output_path or RECONX_OUTPUT_PATH
    actual_output_path.mkdir(parents=True, exist_ok=True)
    return actual_output_path


def run_tool(tool: str, domain: str, timeout: Optional[int] = None,
             threads: int = 10, output_dir: Optional[Path] = None) -> bool:
    """
    Execute a specific tool with the given domain.

    Args:
        tool: Name of the tool script to run
        domain: Target domain for scanning
        timeout: Optional timeout in seconds for the tool execution
        threads: Number of threads for concurrent operations
        output_dir: Optional custom output directory

    Returns:
        bool: True if tool executed successfully, False otherwise
    """
    tool_path = RECONX_MODULES / tool

    if not tool_path.exists():
        logger.error(f"Tool {tool} not found at {tool_path}")
        return False

    try:
        logger.info(f"Running {tool} against {domain}...")
        start_time = time.time()

        cmd = ["python3", str(tool_path), domain]

        # Add optional parameters
        if timeout:
            cmd.extend(["--timeout", str(timeout)])
        if threads:
            cmd.extend(["--threads", str(threads)])
        if output_dir:
            cmd.extend(["--output", str(output_dir)])

        process = subprocess.run(
            cmd,
            check=True,
            timeout=timeout,
            capture_output=True,
            text=True
        )

        # Log tool output at debug level
        for line in process.stdout.splitlines():
            logger.debug(line)

        execution_time = time.time() - start_time
        logger.info(f"Successfully completed {tool} in {execution_time:.2f} seconds")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running {tool}: {e}")
        logger.debug(f"Tool output: {e.stdout}")
        logger.debug(f"Tool error: {e.stderr}")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Tool {tool} timed out after {timeout} seconds")
        return False
    except Exception as e:
        logger.error(f"Unexpected error running {tool}: {str(e)}")
        return False


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="reconX - A Comprehensive Reconnaissance Framework by @0xk4b1r",
        epilog="Example: python3 reconx.py -d example.com --full"
    )

    # Required arguments
    parser.add_argument('-d', '--domain', required=True, help="Target domain for scanning")

    # Individual tool options
    tool_group = parser.add_argument_group('Tool Selection')
    tool_group.add_argument('--subs', action='store_true', help="Run subdomain enumeration")
    tool_group.add_argument('--ports', action='store_true', help="Run port scanning")
    tool_group.add_argument('--urls', action='store_true', help="Run URL enumeration")
    tool_group.add_argument('--nmap', action='store_true', help="Run Nmap scanning")
    tool_group.add_argument('--web', action='store_true', help="Run web enumeration")
    tool_group.add_argument('--js', action='store_true', help="Run JavaScript scanning")
    tool_group.add_argument('--sens', action='store_true', help="Run sensitive information enumeration")
    tool_group.add_argument('--full', action='store_true', help="Run all tools (complete scan)")

    # Additional options
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument('-o', '--output', help="Custom output directory")
    misc_group.add_argument('-t', '--threads', type=int, default=10,
                            help="Number of threads for concurrent operations (default: 10)")
    misc_group.add_argument('--timeout', type=int, default=3600,
                            help="Timeout in seconds for each tool (default: 3600)")
    misc_group.add_argument('-v', '--verbose', action='store_true',
                            help="Enable verbose output")
    misc_group.add_argument('--version', action='version',
                            version=f'reconX v{VERSION}')

    return parser.parse_args()


def main() -> None:
    """Main execution function."""
    # Parse command line arguments
    args = parse_arguments()

    # Set up logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        # Update handler level
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)

    # Display banner
    display_banner()

    # Set custom output path if specified
    output_path = None
    if args.output:
        output_path = Path(args.output)

    # Ensure directories exist
    output_path = ensure_directories_exist(output_path)

    domain = args.domain
    timeout = args.timeout
    threads = args.threads

    # Define the mapping of tools and their corresponding script files
    tools_mapping = {
        'subs': 'subfinder.py',
        'ports': 'port_scanner.py',
        'urls': 'urls_enum.py',
        'nmap': 'nmap.py',
        'web': 'web_enum.py',
        'js': 'js_scan.py',
        'sens': 'sensitive_info_enum.py'
    }

    # Default execution order for --full option
    full_scan_tools = [
        'subfinder.py',
        'port_scanner.py',
        'urls_enum.py',
        'nmap.py',
        'web_enum.py',
        'js_scan.py',
        'sensitive_info_enum.py'
    ]

    # Track tool execution status
    executed_tools = []
    failed_tools = []

    # Run selected tools
    if args.full:
        logger.info(f"Running full reconnaissance on {domain}")
        for tool in full_scan_tools:
            if run_tool(tool, domain, timeout=timeout, threads=threads, output_dir=output_path):
                executed_tools.append(tool)
            else:
                failed_tools.append(tool)
    else:
        # Run individual tools based on options
        any_tool_selected = False
        for option, tool_file in tools_mapping.items():
            if getattr(args, option, False):
                any_tool_selected = True

                # Check dependencies
                if option == 'nmap' and 'port_scanner.py' not in executed_tools:
                    logger.warning("Nmap scanning requires port scanning results. Running port scanner first...")
                    if run_tool('port_scanner.py', domain, timeout=timeout, threads=threads, output_dir=output_path):
                        executed_tools.append('port_scanner.py')
                    else:
                        failed_tools.append('port_scanner.py')
                        logger.error("Port scanning failed. Skipping Nmap scan.")
                        continue

                if option == 'js' and 'urls_enum.py' not in executed_tools:
                    logger.warning(
                        "JavaScript scanning works best with URL enumeration results. Running URL enumeration first...")
                    if run_tool('urls_enum.py', domain, timeout=timeout, threads=threads, output_dir=output_path):
                        executed_tools.append('urls_enum.py')
                    else:
                        logger.warning("URL enumeration failed but continuing with JavaScript scanning...")

                # Run the selected tool
                if run_tool(tool_file, domain, timeout=timeout, threads=threads, output_dir=output_path):
                    executed_tools.append(tool_file)
                else:
                    failed_tools.append(tool_file)

        if not any_tool_selected:
            logger.error("No tools selected. Use --help to see available options.")
            sys.exit(1)

    # Print execution summary
    logger.info("=== Execution Summary ===")
    if executed_tools:
        logger.info(f"Successfully executed: {', '.join(executed_tools)}")
    if failed_tools:
        logger.warning(f"Failed tools: {', '.join(failed_tools)}")

    # Calculate output directory for this domain
    output_dir = output_path / domain
    logger.info(f"Results saved to: {output_dir}")

    # Return the count of failed tools as exit code (0 = all success)
    sys.exit(len(failed_tools))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user. Exiting...")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}")
        sys.exit(1)