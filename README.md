# SecureDNS

SecureDNS is a DNS middleware that enhances DNS resolution with additional security features, such as VirusTotal integration for domain reputation checks, caching using Redis, and logging DNS queries to a SQLite database. It also supports DNS resolution using Google and Cloudflare DNS-over-HTTPS (DoH) services.

This project is built to be used in a Raspberry Pi.

## Features

- **VirusTotal Integration**: Checks domains against VirusTotal to identify malicious domains.
- **Redis Caching**: Caches DNS query results and VirusTotal responses to improve performance.
- **SQLite Logging**: Logs DNS queries and middleware events for auditing and analysis.
- **DNS-over-HTTPS (DoH)**: Resolves domains using Google and Cloudflare DoH services.
- **Customizable Search Suffixes**: Strips specific suffixes from domain names for internal use.
- **NXDOMAIN Handling**: Returns NXDOMAIN for unresolved domains.

---

## How It Works

### 1. **DNS Query Handling**
- The `DNSHandler` class in `dns_handler.py` processes incoming DNS queries.
- It parses the DNS request, extracts the domain name, and checks if it matches specific suffixes or is a reverse DNS lookup.
- The middleware checks if the domain is flagged as malicious using VirusTotal.

### 2. **VirusTotal Integration**
- The `check_virustotal` function in `virustotal.py` queries VirusTotal's API to check if a domain is flagged as malicious.
- Results are cached in Redis for faster subsequent lookups.

### 3. **Caching**
- Redis is used to cache:
  - VirusTotal results (`vt:<domain>`).
  - Resolved IP addresses (`dns:<domain>`).
- Cached results reduce the need for repeated external API calls and DNS queries.

### 4. **DNS Resolution**
- If a domain is not flagged as malicious, the middleware resolves it using:
  - Local DNS resolution (`forward_dns_query` in `dns_utils.py`).
  - Google DoH (`get_ip_addresses_from_google` in `dns_utils.py`).
  - Cloudflare DoH (`get_ip_addresses_from_cloudflare` in `dns_utils.py`).
- Resolved IP addresses are verified across multiple sources for accuracy.

### 5. **Logging**
- All DNS queries and middleware events are logged to a SQLite database (`dns_queries` and `middleware_logs` tables).
- The `log_query` and `log_event` functions in `database.py` handle logging.

### 6. **Middleware Lifecycle**
- The middleware starts and stops gracefully, logging events to the database and log file.
- Signal handlers (`SIGINT` and `SIGTERM`) ensure proper shutdown.

---

## Installation

### Prerequisites
1. Python 3.8 or higher.
2. Redis installed and running on `localhost:6379`.
3. SQLite (pre-installed with Python).
4. `dig` command-line tool (for local DNS resolution).

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/SecureDNS.git
   cd SecureDNS
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure the `.env` file:
   - Add your VirusTotal API key in the `.env` file:
     ```
     VT_API_KEY = "your_virustotal_api_key"
     ```

4. Initialize the SQLite database:
   ```bash
   python database.py
   ```

5. Start the middleware:
   ```bash
   sudo python main.py
   ```

---

## Usage

1. **Start the Middleware**:
   - Run `main.py` to start the DNS middleware.
   - The middleware listens on port 53 for DNS queries.

2. **Query a Domain**:
   - Use a DNS client or tool (e.g., `dig`) to query the middleware:
     ```bash
     dig @127.0.0.1 example.com
     ```

3. **Check Logs**:
   - View logs in the SQLite database (`/var/log/dns_queries.db`) or the log file (`/var/log/dns_middleware.log`).

---

## File Structure

- **`main.py`**: Entry point for the middleware. Sets up logging, initializes the database, and starts the DNS server.
- **`dns_handler.py`**: Handles incoming DNS queries, integrates VirusTotal, and resolves domains.
- **`virustotal.py`**: Queries VirusTotal API and caches results in Redis.
- **`dns_utils.py`**: Provides DNS resolution using Google and Cloudflare DoH services.
- **`database.py`**: Manages SQLite database for logging queries and events.
- **`.env`**: Stores environment variables (e.g., VirusTotal API key).

---

## Configuration

- **VirusTotal API Key**: Set in the `.env` file.
- **Redis Configuration**: Default host is `localhost`, port is `6379`, and database is `0`. Modify in `virustotal.py` if needed.
- **Log File**: Default path is `/var/log/dns_middleware.log`. Modify in `main.py` if needed.
- **Database Path**: Default path is `/var/log/dns_queries.db`. Modify in `database.py` if needed.

---

## Example Workflow

1. A DNS query for `example.com` is received.
2. The middleware checks Redis for cached results.
3. If not cached, it queries VirusTotal to check if the domain is malicious.
4. If safe, it resolves the domain using local DNS, Google DoH, or Cloudflare DoH.
5. The resolved IP address is cached in Redis and returned to the client.
6. The query is logged in the SQLite database.

---

## Troubleshooting

- **Redis Connection Issues**:
  - Ensure Redis is running on `localhost:6379`.
  - Check the Redis configuration in `virustotal.py`.

- **Database Errors**:
  - Ensure the SQLite database file is writable.
  - Check the database path in `database.py`.

- **Port 53 Binding Issues**:
  - Run the middleware with `sudo` to bind to port 53.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgments

- [VirusTotal API](https://www.virustotal.com/)
- [Google DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/dns-over-https)
- [Cloudflare DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/dns-over-https/)

---

## Contributors

- Developed by [Dhivijit Koppuravuri](https://github.com/dhivijit) and [Mokshagna Bhuvan](https://github.com/MokshagnaBhuvan).


