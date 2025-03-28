import signal
import logging
from database import init_db, log_event
from dns_handler import DNSHandler
import socketserver

LOG_FILE = "/var/log/dns_middleware.log"

def setup_logging():
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def shutdown_handler(signum, frame):
    log_event("🔴 DNS Middleware Stopped")
    print("\n🔴 DNS Middleware Stopped")
    exit(0)

if __name__ == "__main__":
    setup_logging()
    init_db()
    log_event("🟢 DNS Middleware Started")
    print("🚀 DNS Middleware Running on Port 53... (Press Ctrl+C to Stop)")

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    with socketserver.UDPServer(("0.0.0.0", 53), DNSHandler) as server:
        server.serve_forever()