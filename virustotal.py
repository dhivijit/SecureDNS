import logging
import requests
import redis
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0

redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

def check_virustotal(domain):
    """Check if a domain is flagged as malicious on VirusTotal, using Redis for caching."""
    print(f"Checking VirusTotal for domain: {domain}")
    logging.info(f"Checking VirusTotal for domain: {domain}")

    cache_key = f"vt:{domain}"
    cached_result = redis_client.get(cache_key)

    if cached_result is not None:
        print(f"🟢 Redis Cache HIT: {domain} -> {cached_result}")
        logging.info(f"🟢 Redis Cache HIT: {domain} -> {cached_result}")
        return cached_result == "malicious"

    print(f"🔄 Redis Cache MISS: Checking VirusTotal for {domain}")
    logging.info(f"🔄 Redis Cache MISS: Checking VirusTotal for {domain}")

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_votes = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

            if malicious_votes > 0:
                redis_client.setex(cache_key, 86400, "malicious")
                print(f"🚨 VirusTotal flagged {domain} as MALICIOUS ({malicious_votes} reports)")
                logging.info(f"🚨 VirusTotal flagged {domain} as MALICIOUS ({malicious_votes} reports)")
                return True

            redis_client.setex(cache_key, 604800, "safe")
            print(f"✅ VirusTotal flagged {domain} as SAFE")
            logging.info(f"✅ VirusTotal flagged {domain} as SAFE")
    except Exception as e:
        print(f"❌ Error checking VirusTotal: {e}")
        logging.error(f"❌ Error checking VirusTotal: {e}")

    return False

if __name__ == "__main__":
    print("This script is not meant to be run directly.")
    print("Please run main.py to start the DNS middleware.")