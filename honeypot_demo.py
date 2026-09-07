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
LOG_FILE = "access_attempts.log" # antes: ARCHIVO_REGISTRO
DB_FILE = "honeypot.db"
MAX_CONTENT_LENGTH = 1024 # Anti DoS
MAX_ATTEMPTS = 5 # Bloquear después de 5 intentos
TIME_WINDOW = 600 # 10 minutos

# Configurar el registro con rotación
log_dir = os.path.dirname(os.path.abspath(LOG_FILE)) or '.'
if not os.access(log_dir, os.W_OK):
    raise PermissionError(f"No hay permisos de escritura para el directorio: {log_dir}")

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
# Evita agregar manejadores duplicados si se recarga el módulo.
if not any(isinstance(h, RotatingFileHandler) and getattr(h, 'baseFilename', '') == os.path.abspath(LOG_FILE) for h in root_logger.handlers):
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    formatter = logging.Formatter('[%(asctime)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

# Almacenamiento en memoria para el conteo de intentos
attempts_by_ip = defaultdict(list) # antes: intentos_por_ip
blocked_ips = set() # antes: direcciones_ip_bloqueadas

# --- Ayudantes de SQLite ---

def init_db():
    """Inicializa la base de datos y las tablas necesarias."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts ( -- antes: intenta
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp REAL NOT NULL,
                username TEXT, -- antes: nombre de usuario
                user_agent TEXT -- antes: agente de usuario
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_ips ( -- antes: blocked_ips estaba bien
                ip TEXT PRIMARY KEY,
                block_date REAL NOT NULL -- antes: fecha_bloque
            )
            """
        )
        conn.commit()

def load_blocked_ips_from_db():
    """Cargar las direcciones IP bloqueadas en la memoria desde la base de datos al iniciar."""
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute("SELECT ip FROM blocked_ips")
        rows = cur.fetchall()
        for row in rows:
            blocked_ips.add(row[0])

def register_attempt_db(ip, username, user_agent, ts):
    """Guarda un intento en la tabla 'attempts'."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO attempts (ip, timestamp, username, user_agent) VALUES (?,?,?,?)",
            (ip, ts, username, user_agent)
        )
        conn.commit()

def block_ip_db(ip):
    """Bloquea una IP y la guarda en la DB."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO blocked_ips (ip, block_date) VALUES (?,?)",
            (ip, time.time())
        )
        conn.commit()

def get_recent_attempts_from_db(ip):
    """Consulta los intentos recientes de la base de datos para reconstruir el estado (intervalo de tiempo)"""
    now = time.time()
    cutoff = now - TIME_WINDOW
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute(
            "SELECT timestamp FROM attempts WHERE ip =? AND timestamp >=? ORDER BY timestamp",
            (ip, cutoff)
        )
        rows = cur.fetchall()
        # rows es una lista de tuplas [(timestamp,),(timestamp,)...]
        timestamps = [r[0] for r in rows]
    return timestamps

class HoneypotHandler(BaseHTTPRequestHandler):

    def is_blocked(self, ip): # antes: is_blocked
        if ip in blocked_ips:
            return True

        # Reconstruir desde DB
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
            self.wfile.write(b"<h1>403 Prohibido</h1><p>IP bloqueada debido a múltiples intentos fallidos.</p>")
            logging.warning(f"Intento de acceso IP bloqueado: {ip}")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html = """
        <!DOCTYPE html>
        <html><head><title>Sistema de demostración - Seguridad</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
            <p style="color:red; font-size:12px;">AVISO: Sistema de demostración. Las direcciones IP se registran por motivos de seguridad.</p>
            <h2>Panel de administración - DEMO</h2>
            <form method="POST">
                <input type="text" name="user" placeholder="Nombre de usuario" required><br><br>
                <input type="password" name="pass" placeholder="Contraseña" required><br><br>
                <button type="submit">Iniciar sesión</button>
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
            # Validar el tipo de contenido mínimo
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('application/x-www-form-urlencoded'):
                self.send_error(400, "Bad Request: tipo de contenido no compatible")
                logging.warning(f"POST rechazado por Content-Type no compatible | IP: {ip} | CT: {content_type}")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_CONTENT_LENGTH:
                self.send_error(413, "Payload Too Large")
                logging.warning(f"POSIBLE DOS | IP: {ip} | Tamaño: {content_length}")
                return

            post_data = self.rfile.read(content_length).decode('utf-8')
            data = urllib.parse.parse_qs(post_data) # antes: datos
            username = data.get('user', [''])[0] # antes: nombre de usuario
