import os
import subprocess

class UrlEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains_dir = os.path.join(domain, 'subdomains')
        self.urls_dir = os.path.join(domain, 'urls')
        self.live_subdomains_file = os.path.join(self.subdomains_dir, 'subdomains.txt')
        self.create_directory_structure()

    def create_directory_structure(self):
        """Create the necessary directories for URLs."""
        os.makedirs(self.urls_dir, exist_ok=True)

    def run_command(self, command, output_file=None):
        """Run a shell command and write its output to a file if provided."""
        try:
            result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
            if output_file:
                with open(output_file, 'a') as f:
                    f.write(result.stdout)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while running: {command}\nError: {e}")
            return ""

    def enumerate_urls(self):
        """Find and enumerate URLs using various tools."""
        waybackurls_file = os.path.join(self.urls_dir, 'waybackurls-urls.txt')
        gau_file = os.path.join(self.urls_dir, 'gau-urls.txt')
        katana_file = os.path.join(self.urls_dir, 'katana-urls.txt')
        hakrawler_file = os.path.join(self.urls_dir, 'hakrawler-urls.txt')

        # Finding URLs
        self.run_command(f"cat {self.live_subdomains_file} | waybackurls", waybackurls_file)
        # self.run_command(f"cat {self.live_subdomains_file} | gau", gau_file)
        # self.run_command(f"cat {self.live_subdomains_file} | katana", katana_file)
        # self.run_command(f"cat {self.live_subdomains_file} | hakrawler", hakrawler_file)

        # Combine and filter URLs
        all_urls_file = os.path.join(self.urls_dir, 'urls.txt')
        combined_urls = f"cat {self.urls_dir}/*-urls.txt | grep -Eo '(http|https)://[a-zA-Z0-9./?=_-]*' | sort -u"
        self.run_command(combined_urls, all_urls_file)

        # Filter URLs with uro
        filtered_urls_file = os.path.join(self.urls_dir, 'filtered-urls.txt')
        self.run_command(f"cat {all_urls_file} | uro", filtered_urls_file)

        # Filter URLs with parameters
        param_urls_file = os.path.join(self.urls_dir, 'param-urls.txt')
        self.run_command(f"cat {filtered_urls_file} | grep '='", param_urls_file)

        # Check live URLs using httpx
        live_filtered_urls_file = os.path.join(self.urls_dir, 'live-filtered-urls.txt')
        self.run_command(f"cat {filtered_urls_file} | httpx", live_filtered_urls_file)

        # Live URLs with parameters
        live_param_urls_file = os.path.join(self.urls_dir, 'live-param-urls.txt')
        self.run_command(f"cat {live_filtered_urls_file} | grep '='", live_param_urls_file)

    def process(self):
        """Run the full URL enumeration process."""
        self.enumerate_urls()


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    enumerator = UrlEnumerator(domain)
    enumerator.process()
