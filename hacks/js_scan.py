import argparse
import os
import subprocess

import requests

def create_directory(domain):
    """Create directory for storing subdomains."""
    output_dir = os.path.join('./test/output', domain)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def enumerate_js_files(domain, output_dir):
    """Enumerate JavaScript files using subdomains and common paths."""
    subdomains_file = os.path.join(output_dir, 'subdomains.txt')
    with open(subdomains_file, 'r') as f:
        subdomains = f.read().splitlines()

    urls_file = os.path.join(output_dir,'urls.txt')
    js_dir = os.path.join(output_dir, 'js')
    js_links = os.path.join(js_dir, 'js_links.txt')

    # Ensure the js directory exists
    os.makedirs(js_dir, exist_ok=True)

    # Read URLs
    with open(urls_file, 'r') as f:
        urls = f.read().splitlines()

    grep_js_urls = [url for url in urls if '.js' in url]


    with open(js_links, 'w') as f:
        f.write("\n".join(grep_js_urls))


    # Enumerate using subjs
    subjs_file = os.path.join(js_dir, 'subjs_output.txt')
    subjs_cmd = f"subjs -i {subdomains_file}"
    subjs_result = subprocess.check_output(subjs_cmd, shell=True, text=True)
    print("subjs_result", subjs_result)

    # for url in grep_js_urls:
    #     response = requests.get(url)
    #     if response.status_code == 200:
    #         clean_url = (
    #             url
    #             .replace('https://', '')
    #             .replace('http://','')
    #             .replace('/','_')
    #         )
    #         response_file = os.path.join(output_dir, 'js', clean_url)
    #         with open(response_file, 'w') as f:
    #             f.write(response.text)
    #     else:
    #         print(f"Failed to retrieve", url)






def main():
    parser = argparse.ArgumentParser(description="JavaScript enumeration tool")
    parser.add_argument('domain', help="Target domain for JavaScript enumeration")
    args = parser.parse_args()

    domain = args.domain
    output_dir = create_directory(domain)
    enumerate_js_files(domain,output_dir)


if __name__ == '__main__':
    main()