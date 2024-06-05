Domain Information Tool

The Domain Information Tool is a comprehensive Python script designed to gather and display detailed information about a given domain. This tool follows redirects, performs WHOIS lookups, checks DNS records, retrieves SSL certificate information, provides historical WHOIS data, checks for blacklist status, and more. It is useful for web administrators, cybersecurity professionals, and anyone interested in obtaining detailed information about a domain.
Features

    - Redirect Following: Tracks and displays the final URL after following all redirects.
    - WHOIS Lookup: Performs a comprehensive WHOIS lookup and displays registrar information, nameservers, creation, expiration dates, and more.
    - DNS Lookup: Uses Cloudflare DoH (DNS over HTTPS) to retrieve DNS records.
    - Hosting Information: Retrieves hosting provider information based on the domain's IP address.
    - SSL Certificate Information: Displays detailed information about the domain's SSL certificate, including issuer, subject, validity dates, and serial number.
    - Historical WHOIS Data: (Requires SecurityTrails API key) Retrieves and displays historical WHOIS records for the domain.
    - Spamhaus Blacklist Check: Checks if the domain's IP address is listed on the Spamhaus blacklist.
    - Domain Health Check: (Requires Google Safe Browsing API key) Checks the domain's safety status using the Google Safe Browsing API.
    - Reverse IP Lookup: Identifies other domains hosted on the same IP address.
    - Domain Age Calculation: Calculates and displays the age of the domain.
    - Detailed Error Handling: Provides meaningful error messages and continues operation even if some API keys are missing.

Installation

    Clone the Repository:

    sh

git clone https://github.com/yourusername/domain-info-tool.git
cd domain-info-tool

Install Dependencies:

This script requires several Python libraries. Install them using pip:

sh

pip install whois requests pycountry pyopenssl

API Keys:

To fully utilize this tool, you need API keys for SecurityTrails and Google Safe Browsing. Replace the placeholders in the script with your actual API keys:

python

    SECURITYTRAILS_API_KEY = 'your_securitytrails_api_key'
    GOOGLE_SAFE_BROWSING_API_KEY = 'your_google_safe_browsing_api_key'

Usage

Run the script with the desired domain URL as a parameter:

sh

python domain_info.py http://example.com

The tool will output detailed information about the domain in a human-readable format.
