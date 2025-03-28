import socketserver
import logging
from dnslib import DNSRecord, QTYPE, RR, A, RCODE
from database import log_query
from dns_utils import get_ip_addresses_from_google, get_ip_addresses_from_cloudflare, forward_dns_query
from virustotal import check_virustotal, redis_client

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]

        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            print(f"❌ Error parsing DNS request: {e}")
            logging.error(f"❌ Error parsing DNS request: {e}")
            return

        domain = str(request.q.qname).rstrip('.')

        # Extract actual client IP from the first query field
        real_client_ip = self.client_address[0]

        SEARCH_SUFFIXES = [".ch.amrita.edu"]
        for suffix in SEARCH_SUFFIXES:
            if domain.endswith(suffix):
                domain = domain.replace(suffix, "")
                break

        # Ignore reverse DNS lookups
        if domain.endswith(".in-addr.arpa"):
            print(f"🔸 Ignoring reverse DNS lookup: {domain}")
            return

        print(f"🔍 DNS Query from {real_client_ip} for {domain}")
        logging.info(f"DNS Query from {real_client_ip} for {domain}")

        # 🔹 Check VirusTotal with Redis cache
        vt_flagged = check_virustotal(domain)
        if vt_flagged:
            print(f"🚨 BLOCKED: {domain} (VirusTotal flagged it as malicious)")
            reply = request.reply()
            # Block response
            reply.add_answer(RR(domain, QTYPE.A, rdata=A("0.0.0.0")))
            socket.sendto(reply.pack(), self.client_address)
            log_query(real_client_ip, domain, False, True)
            return

        # Check Redis cache for DNS resolution
        cache_key = f"dns:{domain}"
        cached_ip = redis_client.get(cache_key)

        if cached_ip:
            print(f"🟢 Redis Cache HIT: {domain} -> {cached_ip}")
            logging.info(f"🟢 Redis Cache HIT: {domain} -> {cached_ip}")
            reply = request.reply()
            reply.add_answer(RR(domain, QTYPE.A, rdata=A(cached_ip)))
            socket.sendto(reply.pack(), self.client_address)
            log_query(real_client_ip, domain, False, False)
            return

        # Forward the DNS query
        resolved_ip = forward_dns_query(domain)

        if resolved_ip:
            googleDNSResults = get_ip_addresses_from_google(domain)
            cloudflareDNSResults = get_ip_addresses_from_cloudflare(domain)

            if resolved_ip in googleDNSResults:
                print(f"✅ Verified {domain} -> {resolved_ip} using Google DNS")
            if resolved_ip in cloudflareDNSResults:
                print(f"✅ Verified {domain} -> {resolved_ip} using Cloudflare DNS")

            print(f"✅ Resolved {domain} -> {resolved_ip}")
            redis_client.setex(cache_key, 3600, resolved_ip)
            reply = request.reply()
            reply.add_answer(RR(domain, QTYPE.A, rdata=A(resolved_ip)))
            socket.sendto(reply.pack(), self.client_address)
            log_query(real_client_ip, domain, False, False)
            return

        googleDNSResults = get_ip_addresses_from_google(domain)
        cloudflareDNSResults = get_ip_addresses_from_cloudflare(domain)

        if googleDNSResults:
            print(f"✅ Resolved {domain} -> {googleDNSResults[0]} using Google DNS")
            redis_client.setex(cache_key, 3600, googleDNSResults[0])
            reply = request.reply()
            reply.add_answer(RR(domain, QTYPE.A, rdata=A(googleDNSResults[0])))
            socket.sendto(reply.pack(), self.client_address)
            log_query(real_client_ip, domain, False, False)
        elif cloudflareDNSResults:
            print(f"✅ Resolved {domain} -> {cloudflareDNSResults[0]} using Cloudflare DNS")
            redis_client.setex(cache_key, 3600, cloudflareDNSResults[0])
            reply = request.reply()
            reply.add_answer(RR(domain, QTYPE.A, rdata=A(cloudflareDNSResults[0])))
            socket.sendto(reply.pack(), self.client_address)
            log_query(real_client_ip, domain, False, False)
        else:
            print(f"⚠️ Failed to resolve {domain}, returning NXDOMAIN")
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
            socket.sendto(reply.pack(), self.client_address)  # Return NXDOMAIN
            log_query(real_client_ip, domain, False, False)

if __name__ == "__main__":
    print("This script is not meant to be run directly.")
    print("Please run main.py to start the DNS middleware.")