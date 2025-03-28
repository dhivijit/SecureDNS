import requests
import subprocess

def get_ip_addresses_from_google(domain):
    url = f"https://dns.google/resolve?name={domain}&type=A"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        ip_addresses = [answer['data'] for answer in data.get('Answer', []) if answer['type'] == 1]
        return sorted(ip_addresses)
    except Exception as e:
        print(f"❌ Error fetching IP addresses for {domain}: {e}")
        return []

def get_ip_addresses_from_cloudflare(domain):
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
    headers = {"Accept": "application/dns-json"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        ip_addresses = [answer['data'] for answer in data.get('Answer', []) if answer['type'] == 1]
        return sorted(ip_addresses)
    except Exception as e:
        print(f"❌ Error fetching IP addresses for {domain} from Cloudflare: {e}")
        return []

def forward_dns_query(domain):
    try:
        output = subprocess.check_output(["dig", "+short", domain], text=True).strip()
        if output:
            resolved_ip = output.split("\n")[0]
            print(f"Resolved IP for {domain}: {resolved_ip}")
            return resolved_ip
    except Exception as e:
        print(f"❌ Error resolving {domain}: {e}")
    return None

if __name__ == "__main__":
    print("This script is not meant to be run directly.")
    print("Please run main.py to start the DNS middleware.")