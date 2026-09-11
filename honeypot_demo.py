from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
import os
import logging
import time
import sqlite3
from collections import defaultdict
from logging.handlers import RotatingFileHandler

# ===== CONFIG =====
PORT = 8080
DB_FILE = "honeypot.db"
MAX_CONTENT_LENGTH = 1024
MAX_ATTEMPTS = 5
TIME_WINDOW = 600  # 10 minutos

LOG_FILE = "access_attempts.log"  # Ajusta según entorno

# Credenciales parametrizadas (no hardcodeadas)
USUARIO_VALIDO = os.getenv("HONEYPOT_USER", "admin")
CONTRASENA_VALIDA = os.getenv("HONEYPOT_PASS", "demo123")

# ===== LOGGING =====
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
if not any(isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    formatter = logging.Formatter('[%(asctime)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

# ===== DB Y MEMORIA =====
attempts_by_ip = defaultdict(list)
blocked_ips = set()

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            timestamp REAL NOT NULL,
            username TEXT,
            user_agent TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            block_date REAL NOT NULL)""")
        conn.commit()

def load_blocked_ips_from_db():
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute("SELECT ip FROM blocked_ips")
        for row in cur.fetchall():
            blocked_ips.add(row[0])

def register_attempt_db(ip, username, user_agent, ts):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO attempts (ip, timestamp, username, user_agent) VALUES (?,?,?,?)",
                     (ip, ts, username, user_agent))
        conn.commit()

def block_ip_db(ip):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip, block_date) VALUES (?,?)", (ip, time.time()))
        conn.commit()

def get_recent_attempts_from_db(ip):
    now = time.time()
    cutoff = now - TIME_WINDOW
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute("SELECT timestamp FROM attempts WHERE ip =? AND timestamp >=? ORDER BY timestamp",
                           (ip, cutoff))
        return [r[0] for r in cur.fetchall()]

def get_stats():
    with sqlite3.connect(DB_FILE) as conn:
        total = conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        last10 = conn.execute("SELECT ip, username, timestamp FROM attempts ORDER BY id DESC LIMIT 10").fetchall()
    return total, blocked, last10

def sanitize(text):
    return "".join(c for c in text if c.isalnum() or c in "-_@.")

# ===== HANDLER =====
class HoneypotHandler(BaseHTTPRequestHandler):
    def is_blocked(self, ip):
        attempts_by_ip[ip] = get_recent_attempts_from_db(ip)
        if len(attempts_by_ip[ip]) >= MAX_ATTEMPTS:
            blocked_ips.add(ip)
            block_ip_db(ip)
            return True
        return False

    def do_GET(self):
        ip = self.client_address[0]
        if self.path == "/panel":
            if ip in blocked_ips:
                self.send_error(403, "Bloqueado temporalmente")
                return
            return self.show_panel(ip)

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html = f"""<!DOCTYPE html><html><head><title>Radar Lite Honeypot</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>body{{font-family:sans-serif;text-align:center;padding-top:50px;background:#0a0a0a;color:#eee}}
       .box{{display:inline-block;padding:30px;border:1px solid #333;border-radius:8px;background:#111}}
        input{{padding:8px;width:200px;margin:5px}} button{{padding:10px 20px;width:216px;background:#0a84ff;border:0;color:white;cursor:pointer}}
        </style></head><body>
        <div class="box">
        <p style="color:red; font-size:12px;">AVISO: Sistema de demostración para portafolio. Se registran IPs.</p>
        <h2>Radar Lite - Admin Panel</h2>
        <form method="POST">
        <input type="text" name="user" placeholder="Usuario" required><br>
        <input type="password" name="pass" placeholder="Contraseña" required><br>
        <button type="submit">Iniciar Sesión</button>
        </form>
        </div></body></html>"""
        self.wfile.write(html.encode("utf-8"))

    def show_panel(self, ip):
        total, blocked, last10 = get_stats()
        rows = "".join([f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[2]))}</td></tr>" for r in last10])
        html = f"""<!DOCTYPE html><html><head><title>Panel</title>
        <style>body{{font-family:sans-serif;padding:20px;background:#0a0a0a;color:#0f0}}
        table{{width:100%;border-collapse:collapse}} td,th{{border:1px solid #333;padding:8px}}</style></head><body>
        <h2>Bienvenido al Panel - Radar Lite</h2>
        <p>IP: {ip} | Usuario: {USUARIO_VALIDO}</p>
        <hr>
        <h3>Estadísticas</h3>
        <p>Total Intentos: {total} | IPs Bloqueadas: {blocked}</p>
        <h3>Últimos 10 Intentos</h3>
        <table><tr><th>IP</th><th>Usuario</th><th>Fecha</th></tr>{rows}</table>
        <br><a href="/" style="color:#0ff;">Cerrar Sesión</a>
        </body></html>"""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        ip = self.client_address[0]
        if self.is_blocked(ip):
            self.send_response(403)
            self.end_headers()
            return
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = urllib.parse.parse_qs(post_data)
            username = sanitize(data.get('user', [''])[0])
            password = sanitize(data.get('pass', [''])[0])
            ua = self.headers.get('User-Agent', 'Unknown')
            ts = time.time()
            register_attempt_db(ip, username, ua, ts)

            if username == USUARIO_VALIDO and password == CONTRASENA_VALIDA:
                logging.info(f"LOGIN EXITOSO | IP: {ip} | User: '{username}'")
                self.send_response(302)
                self.send_header("Location", "/panel")
                self.end_headers()
                return

            attempt_n = len(attempts_by_ip[ip]) + 1
            log_msg = f"LOGIN FALLIDO {attempt_n}/{MAX_ATTEMPTS} | IP: {ip} | User: '{username}'"
            logging.warning(log_msg)
            self.is_blocked(ip)

        except Exception as e:
            logging.error(f"{ip} | Error: {e}")
            self.send_error(500)
            return

        self.send_response(401)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<h3>Acceso Denegado.</h3><p>Usuario o contraseña incorrectos.</p><a href='/'>Volver</a>")

if __name__ == "__main__":
    init_db()
    load_blocked_ips_from_db()
    try:
        print(f"[+] Radar Lite Honeypot corriendo en puerto {PORT}")
        print(f"[+] Demo Login: {USUARIO_VALIDO} / {CONTRASENA_VALIDA}")
        print(f"[+] Panel en: http://localhost:{PORT}/panel")
        server = ThreadingHTTPServer(("0.0.0.0", PORT), HoneypotHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Servidor detenido")
``
