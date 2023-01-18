import argparse
import os
import requests
import nmap
import re
import socket
from vulners import Vulners
os.system('cls' if os.name == 'nt' else 'clear')

text = '''

.##...##..######..#####....####...##......######.
.##...##..##......##..##..##..##..##........##...
.##.#.##..####....#####...##..##..##........##...
.#######..##......##..##..##..##..##........##...
..##.##...######..#####....####...######....##...
.................................................
'''
print("\033[34m" + text + "\033[0m")
# Parse command-line arguments
parser = argparse.ArgumentParser(description='Check if a website is behind a firewall and powered by Joomla or WordPress')
parser.add_argument('-u', '--url', required=True, help='URL of the website to check')
parser.add_argument('-r', '--run-as-root', action='store_true', help='Run the script as root')
args = parser.parse_args()

if args.run_as_root and os.geteuid() != 0:
    print("This script must be run as root")
    exit()

# Parse the hostname from the URL
hostname = args.url.split('://')[-1].split('/')[0]

# Get the website's IP address
website_ip = socket.gethostbyname(hostname)
print(f'Website IP: {website_ip}')

# Initialize the nmap scanner
nm = nmap.PortScanner()

# Perform a firewall scan on the hostname
print("Scanning firewall")
nm.scan(hostname, arguments="-Pn --script firewall-bypass")

if nm[hostname].has_tcp(80) and nm[hostname]['tcp'][80]['state'] == 'open':
    print(f'{hostname} is not behind a firewall')
    # Make GET request to website
    try:
        response = requests.get(args.url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'Error: {e}')
        exit()

    # Search HTML source code for keywords associated with Joomla and WordPress
    if 'joomla' in response.text.lower():
        print(f'{args.url} is powered by Joomla')
        version = re.search("(?<=joomla)[^\"]+", response.text.lower()).group(0)
        print(f'Joomla version: {version}')
        
        # Initialize the Vulners API client
        vulners_api = Vulners()

        # Search for Joomla vulnerabilities
        joomla_vulns = vulners_api.search(f'Joomla {version}')

        # Print the number of vulnerabilities found
        print(f'Number of vulnerabilities found: {len(joomla_vulns)}')

        # Print the details of each vulnerability
        for vuln in joomla_vulns:
            print(vuln)
            
    elif 'wp-content' in response.text.lower():
        print(f'{args.url} is powered by WordPress')
        version = re.search("(?<=wp-content)[^\"]+", response.text.lower()).group(0)
        print(f'WordPress version: {version}')
        
        # Initialize the Vulners API client
        vulners_api = Vulners()

        # Search for WordPress vulnerabilities
        wordpress_vulns = vulners_api.search(f'WordPress {version}')

        # Print the number of vulnerabilities found
        print(f'Number of vulnerabilities found: {len(wordpress_vulns)}')

        # Print the details of each vulnerability
        for vuln in wordpress_vulns:
            print(vuln)
    else:
        print(f'{args.url} is not powered by Joomla or WordPress')
else:
    firewall_hostname = nm[hostname]['hostnames'][0]['name']
    print(f'{hostname} is behind a firewall: {firewall_hostname}')

