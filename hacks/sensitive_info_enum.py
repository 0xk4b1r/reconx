import os
import subprocess
import argparse

import requests


def create_directory(path):
    """Create directory for storing sensitive info enumeration results."""
    output_dir = os.path.join(path)
    os.makedirs(output_dir, exist_ok=True)

    return output_dir

def find_sensitive_files_recon(domain, output_dir):
    """Run sensitive files and directories enumeration."""
    subdomains_file = os.path.join(output_dir, 'subdomains.txt')
    sensitive_files_name = ['.git', 'env.js', '.env']
    results_file = os.path.join(output_dir, 'sensitive_files_results.txt')

    if not os.path.exists(subdomains_file):
        print(f"Subdomains file not found: {subdomains_file}")
        return

    with open(subdomains_file, 'r') as f:
        subdomains = f.read().splitlines()

    results = []

    for subdomain in subdomains:
        for file_name in sensitive_files_name:
            url = f"http://{subdomain}/{file_name}"
            httpx_cmd = f"echo {url} | httpx -silent -no-color"
            try:
                httpx_response = subprocess.check_output(httpx_cmd, shell=True, text=True).strip()
                if httpx_response:
                    results.append(httpx_response)
                    print(httpx_response)
            except subprocess.CalledProcessError as e:
                print(f"Error checking {url}: {e}")

    with open(results_file, 'w') as f:
        f.write("\n".join(results))

    print(f"Sensitive files enumeration completed. Results saved to {results_file}")

def find_sensitive_data_in_files(domain, output_dir):
    """Run sensitive data search in files."""
    urls_file = os.path.join(output_dir, 'urls.txt')
    js_files_output_dir = create_directory(f'./test/output/{domain}/js/js_files')


    with open(urls_file, 'r') as f:
        urls = f.read().splitlines()

    # check if .js file exists
    try:
        for url in urls:
            clean_url = url.replace('/', '_').replace(':', '_').replace('?', '_').replace('&', '_')
            js_file = clean_url
            # if url includes
            if '.js' in url:
                response = requests.get(url)
                if response.status_code == 200:
                    with open(f"{js_files_output_dir}/{js_file}", 'w') as f:
                        f.write(response.text)

    except subprocess.CalledProcessError as e:
        print(f"Error checking {url}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Sensitive files enumeration tool")
    parser.add_argument('domain', help="Target domain for sensitive files enumeration")
    args = parser.parse_args()

    domain = args.domain
    output_dir = create_directory(f'./test/output/{domain}')
    #find_sensitive_files_recon(domain, output_dir)
    find_sensitive_data_in_files(domain, output_dir)

if __name__ == '__main__':
    main()