import sqlite3
import logging
from datetime import datetime

DB_PATH = "/var/log/dns_queries.db"

def init_db():
    """Initialize the database and create tables if they don't exist."""
    print("Initializing database...")
    logging.info("Initializing database...")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            domain TEXT,
            dnssec_validated INTEGER,
            virustotal_flagged INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS middleware_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("Database initialized.")
    logging.info("Database initialized.")

def log_query(client_ip, domain, dnssec_validated, vt_flagged):
    """Log the DNS query in SQLite."""
    print(f"Logging query: {client_ip}, {domain}, {dnssec_validated}, {vt_flagged}")
    logging.info(f"Logging query: {client_ip}, {domain}, {dnssec_validated}, {vt_flagged}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO dns_queries (timestamp, client_ip, domain, dnssec_validated, virustotal_flagged) VALUES (?, ?, ?, ?, ?)",
              (datetime.now(), client_ip, domain, int(dnssec_validated), int(vt_flagged)))
    conn.commit()
    conn.close()
    print("Query logged.")
    logging.info("Query logged.")

def log_event(event):
    """Log middleware events (start, stop) in SQLite and log file."""
    print(f"Logging event: {event}")
    logging.info(f"Logging event: {event}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO middleware_logs (timestamp, event) VALUES (?, ?)", (timestamp, event))
    conn.commit()
    conn.close()
    print(f"Event logged: {event}")
    logging.info(f"Event logged: {event}")

if __name__ == "__main__":
    print("This script is not meant to be run directly.")
    print("Please run main.py to start the DNS middleware.")