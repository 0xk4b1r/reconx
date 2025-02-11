import os
import sys
import subprocess
import argparse
import logging

RECONX_HACKS = os.path.expanduser('./hacks/')
RECONX_OUTPUT_PATH = os.path.expanduser('test/output/')

def logo():
    print('''
    __________
    \______   \ ____   ____  ____   __ _____     ____   ____
    |       _// __ \_/ ___\/  _ \ /    \__  \   / ___\_/ __  \\
    |    |   \  ___/\  \__(  <_> )   |  \/ __ \_/ /_/  >  ___/
    |____|_  /\___  >\___  >____/|___|  (____  /\___  / \___  >
            \/     \/     \/           \/     \//_____/      \/
                           reconX by @0xk4b1r
    ''')

def run_tool(tool, domain):
    """ Execute a specific tool with the given domain. """
    tool_path = os.path.join(RECONX_HACKS, tool)
    if os.path.exists(tool_path):
        try:
            subprocess.run(['python3', tool_path, domain], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running {tool}: {e}")
    else:
        logging.error(f"Tool {tool} not found at {tool_path}.")

def main():
    # Initialize logging
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    logo()

    # Parse arguments
    parser = argparse.ArgumentParser(description="reconX - A Reconnaissance Tool by @0xk4b1r")
    parser.add_argument('--subs', action='store_true', help="Run the subfinder.py tool.")
    parser.add_argument('--ports', action='store_true', help="Run the port_scanner.py tool.")
    parser.add_argument('--urls', action='store_true', help="Run the urls_enum.py tool.")
    parser.add_argument('--nmap', action='store_true', help="Run the nmap.py tool.")
    parser.add_argument('--web', action='store_true', help="Run the web_enum.py tool.")
    parser.add_argument('--js', action='store_true', help="Run the js_scan.py tool.")
    parser.add_argument('--sens', action='store_true', help="Run the sens.py tool.")
    parser.add_argument('--full', action='store_true', help="Run all tools (complete scan).")
    parser.add_argument('-d', '--domain', required=True, help="Target domain for scanning.")
    args = parser.parse_args()

    domain = args.domain

    # Run tools based on options
    if args.subs:
        logging.info(f"Running subdomain finder for domain: {domain}")
        run_tool('subfinder.py', domain)
    elif args.ports:
        logging.info(f"Running port scanner for domain: {domain}")
        run_tool('port_scanner.py', domain)
    elif args.urls:
        logging.info(f"Running URL enumeration for domain: {domain}")
        run_tool('urls_enum.py', domain)
    elif args.nmap:
        logging.info(f"Running URL enumeration for domain: {domain}")
        run_tool('nmap.py', domain)
    elif args.web:
        logging.info(f"Running Web enumeration for domain: {domain}")
        run_tool('web_enum.py', domain)
    elif args.js:
        logging.info(f"Running Web enumeration for domain: {domain}")
        run_tool('js_scan.py', domain)
    elif args.sens:
        logging.info(f"Running sensitive_info_enum enumeration for domain: {domain}")
        run_tool('sensitive_info_enum.py', domain)
    elif args.full:
        logging.info(f"Running full scan for domain: {domain}")
        tools = ['subfinder.py', 'port_scanner.py', 'urls_enum.py', 'nmap.py', 'web_enum.py', 'js_scan.py']
        for tool in tools:
            run_tool(tool, domain)
    else:
        logging.error("Please provide a valid option: --subs, --ports, --urls, or --full")
        sys.exit(1)

if __name__ == '__main__':
    main()