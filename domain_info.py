import whois
import requests
import json
import sys
import pycountry
import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

# Replace with your actual API keys or leave as empty strings
SECURITYTRAILS_API_KEY = ''  # 'your_securitytrails_api_key'
GOOGLE_SAFE_BROWSING_API_KEY = ''  # 'your_google_safe_browsing_api_key'

def ensure_url_schema(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def follow_redirects(url):
    url = ensure_url_schema(url)
    print(f"Following redirects for {url}...")
    try:
        response = requests.get(url, allow_redirects=True)
        redirects = [resp.url for resp in response.history]
        redirects.append(response.url)
        print(f"Final URL after redirects: {response.url}")
        return response.url
    except Exception as e:
        print(f"Failed to follow redirects: {e}")
        return url

def perform_whois(domain):
    print(f"Performing WHOIS lookup for {domain}...")
    try:
        w = whois.whois(domain)
        for key, value in w.items():
            if isinstance(value, datetime):
                w[key] = value.isoformat()
            elif isinstance(value, list):
                w[key] = [v.isoformat() if isinstance(v, datetime) else v for v in value]
        print("WHOIS lookup completed.")
        return w
    except Exception as e:
        print(f"WHOIS lookup failed: {e}")
        return {"error": str(e)}

def dns_lookup(domain):
    print(f"Performing DNS lookup for {domain} using Cloudflare DoH...")
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
        headers = {
            'accept': 'application/dns-json'
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            dns_data = response.json()
            result = {}
            for answer in dns_data.get("Answer", []):
                record_type = answer["type"]
                record_value = answer["data"]
                if record_type == 1:  # 'A' record type
                    result.setdefault("A", []).append(record_value)
            print("DNS lookup completed.")
            return result
        else:
            print(f"Failed to retrieve DNS information. Status code: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        print(f"DNS lookup failed: {e}")
        return {"error": str(e)}

def get_country_name(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country.name if country else "Unknown"
    except Exception:
        return "Unknown"

def get_hosting_info(ip):
    print(f"Retrieving hosting provider information for IP {ip}...")
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            hosting_provider = data.get("org", "Unknown")
            country_code = data.get("country", "Unknown")
            country_name = get_country_name(country_code)
            print("Hosting provider information retrieved.")
            return {"hosting_provider": hosting_provider, "country_code": country_code, "country_name": country_name}
        else:
            print(f"Failed to retrieve hosting provider information. Status code: {response.status_code}")
            return {"hosting_provider": "Unknown", "country_code": "Unknown", "country_name": "Unknown"}
    except Exception as e:
        print(f"Failed to retrieve hosting provider information: {e}")
        return {"hosting_provider": "Unknown", "country_code": "Unknown", "country_name": "Unknown"}

def follow_ip_redirects(ip):
    hosting_provider_url = f"http://{ip}"
    final_ip_url = follow_redirects(hosting_provider_url)
    return final_ip_url

def get_ssl_certificate_info(domain):
    print(f"Retrieving SSL certificate information for {domain}...")
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
    s.settimeout(5.0)
    try:
        s.connect((domain, 443))
        cert = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        cert_info = {
            "issuer": dict(x509.get_issuer().get_components()),
            "subject": dict(x509.get_subject().get_components()),
            "notBefore": x509.get_notBefore().decode(),
            "notAfter": x509.get_notAfter().decode(),
            "serialNumber": x509.get_serial_number(),
        }
        print("SSL certificate information retrieved.")
        return cert_info
    except Exception as e:
        print(f"SSL certificate retrieval failed: {e}")
        return {"error": str(e)}

def get_historical_whois(domain):
    if not SECURITYTRAILS_API_KEY:
        print("Warning: SECURITYTRAILS_API_KEY is missing. Skipping historical WHOIS lookup.")
        return {"error": "API key missing"}
    
    print(f"Retrieving historical WHOIS information for {domain}...")
    url = f"https://api.securitytrails.com/v1/history/{domain}/whois"
    headers = {
        "APIKEY": SECURITYTRAILS_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print("Historical WHOIS information retrieved.")
            return data
        else:
            print(f"Failed to retrieve historical WHOIS information. Status code: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        print(f"Historical WHOIS retrieval failed: {e}")
        return {"error": str(e)}

def check_spamhaus_blacklist(ip):
    print(f"Checking if IP {ip} is on any Spamhaus blacklist...")
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        blacklist_zones = [
            "zen.spamhaus.org"
        ]
        listed_zones = []
        for zone in blacklist_zones:
            query = f"{reversed_ip}.{zone}"
            try:
                socket.gethostbyname(query)
                listed_zones.append(zone)
            except socket.gaierror:
                continue
        if listed_zones:
            return {"listed_on": listed_zones}
        else:
            return {"listed_on": []}
    except Exception as e:
        print(f"Spamhaus blacklist check failed: {e}")
        return {"error": str(e)}

def check_domain_health(domain):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        print("Warning: GOOGLE_SAFE_BROWSING_API_KEY is missing. Skipping domain health check.")
        return {"error": "API key missing"}
    
    print(f"Checking domain health for {domain}...")
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {
            "clientId": "yourcompany",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": domain}
            ]
        }
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            data = response.json()
            print("Domain health check completed.")
            return data
        else:
            print(f"Failed to check domain health. Status code: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        print(f"Domain health check failed: {e}")
        return {"error": str(e)}

def reverse_ip_lookup(ip):
    print(f"Performing reverse IP lookup for {ip}...")
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        response = requests.get(url)
        if response.status_code == 200:
            domains = response.text.split('\n')
            print("Reverse IP lookup completed.")
            return domains
        else:
            print(f"Failed to perform reverse IP lookup. Status code: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        print(f"Reverse IP lookup failed: {e}")
        return {"error": str(e)}

def calculate_domain_age(creation_date):
    if creation_date:
        creation_date = datetime.strptime(creation_date, "%Y-%m-%dT%H:%M:%S")
        current_date = datetime.now()
        age = current_date - creation_date
        return age.days
    return None

def main(url):
    final_url = follow_redirects(url)
    final_domain = final_url.split("//")[-1].split("/")[0].split(":")[0]
    
    whois_data = perform_whois(final_domain)
    dns_data = dns_lookup(final_domain)
    
    if 'A' in dns_data and dns_data['A']:
        ip = dns_data['A'][0]
        hosting_info = get_hosting_info(ip)
        final_ip_url = follow_ip_redirects(ip)
        hosting_info["redirects"] = final_ip_url
    else:
        hosting_info = {"hosting_provider": "Unknown", "country_code": "Unknown", "country_name": "Unknown", "redirects": "No A record found"}

    ssl_info = get_ssl_certificate_info(final_domain)
    historical_whois_info = get_historical_whois(final_domain)
    blacklist_info = check_spamhaus_blacklist(ip)
    domain_health = check_domain_health(final_domain)
    reverse_ip_info = reverse_ip_lookup(ip) if 'A' in dns_data and dns_data['A'] else ["No IP found"]
    domain_age = calculate_domain_age(whois_data.get("creation_date"))

    # Convert WHOIS country code to full country name if present
    if isinstance(whois_data, dict) and "country" in whois_data:
        whois_country_name = get_country_name(whois_data["country"])
        whois_data["country"] = whois_country_name

    # Print the results in a human-readable format
    print("\nResults:")
    print(f"Final URL: {final_url}")
    
    print("\nWHOIS Information:")
    if isinstance(whois_data, dict) and "error" not in whois_data:
        for key, value in whois_data.items():
            if isinstance(value, list):
                print(f"{key.capitalize()}:")
                for item in value:
                    print(f"  - {item}")
            else:
                print(f"{key.capitalize()}: {value}")
    else:
        print(f"Error: {whois_data.get('error', 'Unknown error')}")

    print("\nDNS Records:")
    if isinstance(dns_data, dict) and "error" not in dns_data:
        for record_type, records in dns_data.items():
            print(f"{record_type} Records:")
            for record in records:
                print(f"  - {record}")
    else:
        print(f"Error: {dns_data.get('error', 'Unknown error')}")

    print("\nSSL Certificate Information:")
    if isinstance(ssl_info, dict) and "error" not in ssl_info:
        for key, value in ssl_info.items():
            if isinstance(value, dict):
                print(f"{key.capitalize()}:")
                for subkey, subvalue in value.items():
                    print(f"  - {subkey}: {subvalue}")
            else:
                print(f"{key.capitalize()}: {value}")
    else:
        print(f"Error: {ssl_info.get('error', 'Unknown error')}")

    print("\nHistorical WHOIS Information:")
    if isinstance(historical_whois_info, dict) and "error" not in historical_whois_info:
        if "result" in historical_whois_info:
            for entry in historical_whois_info["result"]:
                if isinstance(entry, dict):
                    print("Historical WHOIS Record:")
                    for key, value in entry.items():
                        print(f"  {key}: {value}")
                else:
                    print(f"  {entry}")
        else:
            print("No historical WHOIS data found.")
    else:
        print(f"Error: {historical_whois_info.get('error', 'Unknown error')}")

    print("\nBlacklist Information:")
    if isinstance(blacklist_info, dict) and "error" not in blacklist_info:
        if "listed_on" in blacklist_info and blacklist_info["listed_on"]:
            print(f"Domain is listed on the following blacklists: {', '.join(blacklist_info['listed_on'])}")
        else:
            print("Domain is not listed on any blacklists.")
    else:
        print(f"Error: {blacklist_info.get('error', 'Unknown error')}")

    print("\nDomain Health Information:")
    if isinstance(domain_health, dict) and "error" not in domain_health:
        if "matches" in domain_health:
            print("Domain is flagged as potentially unsafe.")
        else:
            print("Domain is safe.")
    else:
        print(f"Error: {domain_health.get('error', 'Unknown error')}")

    print("\nReverse IP Information from hackertarget.com:")
    if isinstance(reverse_ip_info, list):
        if reverse_ip_info:
            print("Other domains hosted on the same IP:")
            for domain in reverse_ip_info:
                print(f"  - {domain}")
        else:
            print("No other domains found on the same IP.")
    else:
        print(f"Error: {reverse_ip_info}")

    print("\nDomain Age:")
    if domain_age is not None:
        print(f"Domain age: {domain_age} days")
    else:
        print("Domain creation date not available.")

    print("\nHosting Provider Information:")
    print(f"Hosting Provider: {hosting_info['hosting_provider']}")
    print(f"Country: {hosting_info['country_name']}")
    print(f"Hosting Provider Redirects: {hosting_info['redirects']}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <url>")
    else:
        url = sys.argv[1]
        main(url)
