from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
import os
import logging
import time
import sqlite3
from collections import defaultdict
from logging.handlers import RotatingFileHandler

PORT = 8080
LOG_FILE = "access_attempts.log"
DB_FILE = "honeypot.db"
MAX_CONTENT_LENGTH = 1024
MAX_ATTEMPTS = 5
TIME_WINDOW = 600

# Configurar logging con rotacion
log_dir = os.path.dirname(os.path.abspath(LOG_FILE)) or '.'
if not os.access(log_dir, os.W_OK):
    raise PermissionError(f"No hay permisos de escritura para el directorio: {log_dir}")

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
if not any(isinstance(h, RotatingFileHandler) and getattr(h, 'baseFilename', '') == os.path.abspath(LOG_FILE) for h in root_logger.handlers):
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    formatter = logging.Formatter('[%(asctime)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

# Almacenamiento en memoria
attempts_by_ip = defaultdict(list)
blocked_ips = set()

def init_db():
    """Inicializa la base de datos y las tablas necesarias."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, timestamp REAL NOT NULL, username TEXT, user_agent TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, block_date REAL NOT NULL)")
        conn.commit()

def load_blocked_ips_from_db():
    """Cargar las direcciones IP bloqueadas en la memoria desde la base de datos al iniciar."""
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute("SELECT ip FROM blocked_ips")
        for row in cur.fetchall():
            blocked_ips.add(row[0])

def register_attempt_db(ip, username, user_agent, ts):
    """Guarda un intento en la tabla 'attempts'."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO attempts (ip, timestamp, username, user_agent) VALUES (?,?,?,?)", (ip, ts, username, user_agent))
        conn.commit()

def block_ip_db(ip):
    """Bloquea una IP y la guarda en la DB."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip, block_date) VALUES (?,?)", (ip, time.time()))
        conn.commit()

def get_recent_attempts_from_db(ip):
    """Consulta los intentos recientes de la base de datos para reconstruir el estado."""
    now = time.time()
    cutoff = now - TIME_WINDOW
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute("SELECT timestamp FROM attempts WHERE ip =? AND timestamp >=? ORDER BY timestamp", (ip, cutoff))
        return [r[0] for r in cur.fetchall()]

class HoneypotHandler(BaseHTTPRequestHandler):

    def is_blocked(self, ip):
        if ip in blocked_ips:
            return True
        attempts_by_ip[ip] = get_recent_attempts_from_db(ip)
        if len(attempts_by_ip[ip]) >= MAX_ATTEMPTS:
            blocked_ips.add(ip)
            block_ip_db(ip)
            return True
        return False

    def do_GET(self):
        ip = self.client_address[0]
        if self.is_blocked(ip):
            self.send_response(403)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden</h1><p>IP bloqueada por multiples intentos fallidos.</p>")
            logging.warning(f"IP BLOQUEADA intento acceso: {ip}")
            return
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html = """<!DOCTYPE html><html><head><title>Demo Security System</title></head><body style="font-family:sans-serif; text-align:center; padding-top:50px;"><p style="color:red; font-size:12px;">AVISO: Sistema de demostracion. Se registran IPs.</p><h2>Admin Panel - DEMO</h2><form method="POST"><input type="text" name="user" placeholder="Usuario" required><br><br><input type="password" name="pass" placeholder="Contrasena" required><br><br><button type="submit">Login</button></form></body></html>"""
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        ip = self.client_address[0]
        if self.is_blocked(ip):
            self.send_response(403)
            self.end_headers()
            return
        try:
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('application/x-www-form-urlencoded'):
                self.send_error(400, "Bad Request: Invalid Content-Type")
                return
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_CONTENT_LENGTH:
                self.send_error(413, "Payload Too Large")
                return
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = urllib.parse_qs(post_data)
            username = data.get('user', [''])[0]
            ua = self.headers.get('User-Agent', 'Unknown')
            ts = time.time()
            register_attempt_db(ip, username, ua, ts)
            is_blocked_now = self.is_blocked(ip)
            attempt_n = len(attempts_by_ip[ip])
            log_msg = f"ATTEMPT {attempt_n}/{MAX_ATTEMPTS} | IP: {ip} | User: '{username}'"
            logging.info(log_msg)
            print(f"[!] {log_msg}")
            if is_blocked_now:
                logging.critical(f"IP BLOCKED: {ip}")
        except Exception as e:
            logging.error(f"{ip} | Error: {e}")
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<h3>Access Denied. Event logged.</h3><a href='/'>Back</a>")

if __name__ == "__main__":
    init_db()
    load_blocked_ips_from_db()
    try:
        print(f"[+] Honeypot PRO v4.2 running on port {PORT}")
        server = ThreadingHTTPServer(("0.0.0.0", PORT), HoneypotHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Server stopped")
