import os
import sys
import subprocess
import argparse
import os
import requests
import zipfile
import re

# ANSI color codes for text formatting
reset = "\033[0m"
yellow = "\033[1;33m"
green = "\033[0;32m"
cyan = "\033[0;36m"
red = "\033[0;31m"

# Print welcome message
def print_banner():
    print(f"{yellow}{"""\n HRC Automation \n"""}{reset}")

# Usage information function
def print_usage():
    print("Usage: script.py [-d domain] [-l subdomains_file]")
    print("Options:")
    print("  -d domain             Specify the domain to enumerate subdomains (default: highradius.com)")
    print("  -l subdomains_file    Specify a file containing a list of subdomains")
    print("  -h                    Display this help message")
    sys.exit(1)

# Initialize tokens/variables
gitT = ""  # GitHub access token (replace with actual token)
gitL = ""  # GitLab access token (replace with actual token)
knockpyvirusapi = ""  # VirusTotal API Key

# Define output directory and file paths
output_dir = "Automation-script-output"
subdirectories = ["Subdomains", "Cloudsnidomains", "Resolvers", "Wordlists"]
output_files = {
    "sni_domains": os.path.join(output_dir, "Cloudsnidomains", "sni_domains.txt"),
    "file0": os.path.join(output_dir, "Subdomains", "all_subdomains.txt"),
    "file1": os.path.join(output_dir, "final_subdomains.txt"),
    "file2": os.path.join(output_dir, "httpx_output_live_with_status_code.txt"),
    "file3": os.path.join(output_dir, "modified_subdomains.txt"),
    "file4": os.path.join(output_dir, "dnsx_ip_address.txt"),
    "file5": os.path.join(output_dir, "ip_address.txt"),
    "file6": os.path.join(output_dir, "cdncheck_output.txt"),
    "file7": os.path.join(output_dir, "cdncheck_sanitize.txt"),
    "file8": os.path.join(output_dir, "ssl_out.txt"),
    "file9": os.path.join(output_dir, "ssl_out_sanitize.txt"),
    "file10": os.path.join(output_dir, "ssl_final.txt"),
    "file11": os.path.join(output_dir, "certcheck_combined_output.txt"),
    "file12": os.path.join(output_dir, "certcheck_final.txt"),
    "file13": os.path.join(output_dir, "inactive_subdomains.txt"),
    "file14": os.path.join(output_dir, "katana_output.txt"),
    "file15": os.path.join(output_dir, "waybackurls_output.txt"),
    "inactive_old": os.path.join(output_dir, "inactive_subdomains_old.txt"),
    "output_sheet1_csv": os.path.join(output_dir, "output_sheet1.csv"),
    "output_sheet2_csv": os.path.join(output_dir, "output_sheet2.csv"),
    "output_sheet3_csv": os.path.join(output_dir, "output_sheet3.csv"),
    "output_sheet4_csv": os.path.join(output_dir, "output_sheet4.csv"),
    "output_sheet5_csv": os.path.join(output_dir, "output_sheet5.csv"),
}

# Create output directory and subdirectories
os.makedirs(output_dir, exist_ok=True)
for sub in subdirectories:
    os.makedirs(os.path.join(output_dir, sub), exist_ok=True)

def check_tools_installation():
    # Required tools check
    required_tools = ["assetfinder", "subfinder", "waybackurls", "findomain", "sublister", 
                    "amass", "gau", "curl", "jq", "duplicut", "httpx", "dnsx", 
                    "cdncheck", "sslscan", "certcheck", "katana", "nuclei"]

    for tool in required_tools:
        result = subprocess.run(f"command -v {tool}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            print(f"{red}[!] Error: {tool} is not installed. Please install it before running the script.{reset}")
            sys.exit(1)

    print(f"{green}All required tools are installed.{reset}")

def download_file(url, dest_path):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(dest_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        print(f"{cyan}Downloaded: {dest_path}{reset}")
    except requests.RequestException as e:
        print(f"{red}Download failed for {url}. Error: {e}{reset}")
        exit(1)

def resolver_download():
    """Download the resolvers file if it doesn't exist."""
    print(f"{yellow}[*] Checking for resolvers file...{reset}")
    resolver_url = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    resolver_dir = os.path.join(output_dir, "Resolvers")
    resolver_file = os.path.join(resolver_dir, "resolvers.txt")
    
    os.makedirs(resolver_dir, exist_ok=True)
    if not os.path.isfile(resolver_file):
        print(f"{yellow}[*] Downloading resolvers file...{reset}")
        download_file(resolver_url, resolver_file)
    else:
        print(f"{cyan}Resolvers file already exists: {resolver_file}{reset}")

def wordlists_download():
    """Download the wordlists file if it doesn't exist."""
    print(f"{yellow}[*] Checking for wordlists file...{reset}")
    wordlists_url = "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/subdomains.txt"
    wordlists_dir = os.path.join(output_dir, "Wordlists")
    wordlist_file = os.path.join(wordlists_dir, "subdomains.txt")
    
    os.makedirs(wordlists_dir, exist_ok=True)
    if not os.path.isfile(wordlist_file):
        print(f"{yellow}[*] Downloading wordlists file...{reset}")
        download_file(wordlists_url, wordlist_file)
    else:
        print(f"{cyan}Wordlists file already exists: {wordlist_file}{reset}")

def n0kovo_subdomains_wordlists_download():
    """Download and extract the n0kovo subdomains wordlists if not already present."""
    print(f"{yellow}[*] Checking for n0kovo subdomains...{reset}")
    n0kovo_url = "https://github.com/n0kovo/n0kovo_subdomains/archive/refs/heads/main.zip"
    n0kovo_dir = os.path.join(output_dir, "Wordlists")
    n0kovo_extracted_dir = os.path.join(n0kovo_dir, "n0kovo_subdomains")
    
    os.makedirs(n0kovo_dir, exist_ok=True)
    if not os.path.isdir(n0kovo_extracted_dir):
        print(f"{yellow}[*] Downloading and extracting n0kovo subdomains...{reset}")
        zip_path = os.path.join(n0kovo_dir, "main.zip")
        download_file(n0kovo_url, zip_path)
        
        # Extract the zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(n0kovo_dir)
        os.rename(os.path.join(n0kovo_dir, "n0kovo_subdomains-main"), n0kovo_extracted_dir)
        os.remove(zip_path)
        print(f"{cyan}n0kovo subdomains downloaded and extracted.{reset}")
    else:
        print(f"{cyan}n0kovo subdomains already exist: {n0kovo_extracted_dir}{reset}")

def seclists_download():
    """Download and extract the SecLists if not already present."""
    print(f"{yellow}[*] Checking for SecLists...{reset}")
    seclists_url = "https://github.com/danielmiessler/SecLists/archive/master.zip"
    seclists_dir = output_dir
    seclists_extracted_dir = os.path.join(seclists_dir, "Seclists")
    
    os.makedirs(seclists_dir, exist_ok=True)
    if not os.path.isdir(seclists_extracted_dir):
        print(f"{yellow}[*] Downloading and extracting SecLists...{reset}")
        zip_path = os.path.join(seclists_dir, "master.zip")
        download_file(seclists_url, zip_path)
        
        # Extract the zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(seclists_dir)
        os.rename(os.path.join(seclists_dir, "SecLists-master"), seclists_extracted_dir)
        os.remove(zip_path)
        print(f"{cyan}SecLists downloaded and extracted.{reset}")
    else:
        print(f"{cyan}SecLists already exist: {seclists_extracted_dir}{reset}")

def download_necessary_files():
    """Download Google IPs SNI file and filter content based on the domain."""
    print(f"{yellow}[*] Downloading Cloudsnidomains necessary files{reset}")

    # Set the URL of the Google SNI IP file
    google_ips_url = "https://kaeferjaeger.gay/sni-ip-ranges/google/ipv4_merged_sni.txt"
    google_ips_path = os.path.join(output_dir, "Cloudsnidomains", "google_ips.txt")

    # Check if the file already exists
    if os.path.isfile(google_ips_path):
        print(f"{cyan}Google IPs SNI file already exists: {google_ips_path}{reset}")
    else:
        # Download the file if it doesn't exist
        try:
            print(f"{yellow}[*] Downloading google IPs SNI file...{reset}")
            response = requests.get(google_ips_url)
            response.raise_for_status()
            
            with open(google_ips_path, 'wb') as file:
                file.write(response.content)
            print(f"{cyan}Google IPs SNI file downloaded successfully.{reset}")
        
        except requests.RequestException as e:
            print(f"{red}[!] Download failed for {google_ips_url}. Error: {e}{reset}")
            return

    # Filter the downloaded file content based on the domain
    domain_prefix = domain.split('.')[0]  # Get the prefix of the domain (e.g., "example" from "example.com")
    matching_ips = set()

    # Read the file and filter lines containing the domain prefix
    with open(google_ips_path, 'r') as file:
        for line in file:
            if domain_prefix in line:
                # Extract IP ranges within brackets
                ips_in_line = re.findall(r'\[(.*?)\]', line)
                for ip_block in ips_in_line:
                    for ip in ip_block.split():  # Split by whitespace (mimics `sed 's/\s\+/\n/g'`)
                        if ip and ip != "*":  # Filter out any empty items or '*' (mimics `grep -v '^*'`)
                            matching_ips.add(ip)

    # Write the filtered IPs to the output file
    with open(output_files['sni_domains'], 'w') as sni_file:
        sni_file.write('\n'.join(sorted(matching_ips)))  # Remove duplicates with set and sort the list
    print(f"{cyan}Filtered SNI domains saved successfully to {output_files['sni_domains']}.{reset}")

if __name__=="__main__":
    parser = argparse.ArgumentParser(
        description="Enumerate subdomains for a specified domain.",
        usage="script.py [-d domain] [-l subdomains_file]"
    )
    
    # Define arguments
    parser.add_argument(
        '-d', 
        type=str, 
        default="highradius.com", 
        help="Specify the domain to enumerate subdomains (default: highradius.com)"
    )
    parser.add_argument(
        '-l', 
        type=str, 
        help="Specify a file containing a list of subdomains"
    )
    
    # Parse the arguments
    args = parser.parse_args()

    # Print Banner
    print_banner()

    domain = args.d
    subdomains_file=args.l

    # Print parsed arguments for demonstration
    print(f"Domain: {domain}")
    print(f"Subdomains file: {subdomains_file}")

    check_tools_installation()
    resolver_download()
    wordlists_download()
    n0kovo_subdomains_wordlists_download()
    seclists_download()
    download_necessary_files()