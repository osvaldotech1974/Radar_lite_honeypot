from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
import datetime
import os
import logging
import time
import sqlite3
from collections import defaultdict
from logging.handlers import RotatingFileHandler

PORT = 8080
LOG_FILE = "access_attempts.log"
DB_FILE = "honeypot.db"
MAX_CONTENT_LENGTH = 1024  # Anti DoS
MAX_ATTEMPTS = 5  # Block after 5 attempts
TIME_WINDOW = 600  # 10 minutes

# Configure logging with rotation
log_dir = os.path.dirname(os.path.abspath(LOG_FILE)) or '.'
if not os.access(log_dir, os.W_OK):
    raise PermissionError(f"No write permissions for directory: {log_dir}")

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
# Avoid adding duplicate handlers if module is reloaded
if not any(isinstance(h, RotatingFileHandler) and getattr(h, 'baseFilename', '') == os.path.abspath(LOG_FILE) for h in root_logger.handlers):
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    formatter = logging.Formatter('[%(asctime)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

# In-memory storage for counting attempts
attempts_by_ip = defaultdict(list)
blocked_ips = set()

# --- SQLite helpers ---

def init_db():
    """Initialize the database and required tables."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp REAL NOT NULL,
                username TEXT,
                user_agent TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                block_date REAL NOT NULL
            )
            """
        )
        conn.commit()


def load_blocked_ips_from_db():
    """Load blocked IPs into memory from database on startup."""
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute("SELECT ip FROM blocked_ips")
        rows = cur.fetchall()
        for row in rows:
            blocked_ips.add(row[0])


def register_attempt_db(ip, username, user_agent, ts):
    """Save an attempt to the 'attempts' table."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO attempts (ip, timestamp, username, user_agent) VALUES (?,?,?,?)",
            (ip, ts, username, user_agent)
        )
        conn.commit()


def block_ip_db(ip):
    """Persist block in the 'blocked_ips' table and add to memory."""
    now = time.time()
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO blocked_ips (ip, block_date) VALUES (?,?)",
            (ip, now)
        )
        conn.commit()
    blocked_ips.add(ip)

# Initialize DB and load existing blocks
init_db()
load_blocked_ips_from_db()

class HoneypotHandler(BaseHTTPRequestHandler):

    def is_blocked(self, ip):
        # If already explicitly blocked in memory, return True immediately
        if ip in blocked_ips:
            return True

        # Query recent attempts from DB to rebuild state (time window)
        now = time.time()
        cutoff = now - TIME_WINDOW
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.execute(
                "SELECT timestamp FROM attempts WHERE ip = ? AND timestamp >= ? ORDER BY timestamp",
                (ip, cutoff)
            )
            rows = cur.fetchall()
            # rows is list of tuples [(timestamp,),(timestamp,)...]
            timestamps = [r[0] for r in rows]

        # Update memory with recent attempts
        attempts_by_ip[ip] = timestamps

        # If count exceeds maximum, block and persist
        if len(attempts_by_ip[ip]) >= MAX_ATTEMPTS:
            block_ip_db(ip)
            return True

        return False

    def do_GET(self):
        ip = self.client_address[0]
        if self.is_blocked(ip):
            self.send_response(403)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden</h1><p>IP blocked due to multiple failed attempts.</p>")
            logging.warning(f"BLOCKED IP access attempt: {ip}")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html = """
        <!DOCTYPE html>
        <html><head><title>Demo System - Security</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
            <p style="color:red; font-size:12px;">NOTICE: Demo system. IPs are recorded for security purposes.</p>
            <h2>Administration Panel - DEMO</h2>
            <form method="POST">
                <input type="text" name="user" placeholder="Username" required><br><br>
                <input type="password" name="pass" placeholder="Password" required><br><br>
                <button type="submit">Login</button>
            </form>
        </body></html>
        """
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        ip = self.client_address[0]
        if self.is_blocked(ip):
            self.send_response(403)
            self.end_headers()
            return

        try:
            # Validate minimum Content-Type
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('application/x-www-form-urlencoded'):
                self.send_error(400, "Bad Request - unsupported Content-Type")
                logging.warning(f"POST rejected for unsupported Content-Type | IP: {ip} | CT: {content_type}")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_CONTENT_LENGTH:
                self.send_error(413, "Payload Too Large")
                logging.warning(f"POSSIBLE DOS | IP: {ip} | Size: {content_length}")
                return

            post_data = self.rfile.read(content_length).decode('utf-8')
            data = urllib.parse_qs(post_data)
            username = data.get('user', [''])[0]
            ua = self.headers.get('User-Agent', 'Unknown')

            ts = time.time()
            # Register attempt in DB (persistence required)
            register_attempt_db(ip, username, ua, ts)

            # Rebuild / update recent attempts from DB and verify block
            is_blocked = self.is_blocked(ip)

            attempt_n = len(attempts_by_ip[ip])
            log_msg = f"ATTEMPT {attempt_n}/{MAX_ATTEMPTS} | IP: {ip} | Username: '{username}' | UA: {ua}"
            logging.info(log_msg)
            print(f"[!] {log_msg}")

            if is_blocked:
                logging.critical(f"IP BLOCKED: {ip} for exceeding {MAX_ATTEMPTS} attempts")

        except ValueError:
            self.send_error(400, "Bad Request")
        except Exception as e:
            logging.error(f"{ip} | Error: {e}")
            self.send_error(500, "Internal Server Error")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<h3>Access denied. Event recorded.</h3><a href='/'>Back</a>")

if __name__ == "__main__":
    try:
        print(f"[+] Honeypot PRO v3.1 running on port {PORT}")
        print(f"[+] Automatic block after {MAX_ATTEMPTS} attempts in {TIME_WINDOW/60} min")
        server = ThreadingHTTPServer(("0.0.0.0", PORT), HoneypotHandler)
        server.serve_forever()
    except OSError as e:
        print(f"[ERROR] Could not start server on port {PORT}: {e}")
    except KeyboardInterrupt:
        print("\n[+] Server stopped manually")
