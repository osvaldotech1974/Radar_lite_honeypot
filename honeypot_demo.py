from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
import datetime
import os
import logging
import time
from collections import defaultdict
from logging.handlers import RotatingFileHandler

PORT = 8080
LOG_FILE = "intentos_acceso.log"
MAX_CONTENT_LENGTH = 1024 # Anti DoS
MAX_INTENTOS = 5 # Bloquear tras 5 intentos
VENTANA_TIEMPO = 600 # 10 minutos

# Configurar logging con rotación mínima
log_dir = os.path.dirname(os.path.abspath(LOG_FILE)) or '.'
if not os.access(log_dir, os.W_OK):
    raise PermissionError(f"No hay permisos para escribir en {log_dir}")

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
# Evitar añadir handlers duplicados si el módulo se recarga
if not any(isinstance(h, RotatingFileHandler) and getattr(h, 'baseFilename', '') == os.path.abspath(LOG_FILE) for h in root_logger.handlers):
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    formatter = logging.Formatter('[%(asctime)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

# Memoria en RAM para contar intentos
intentos_por_ip = defaultdict(list)
ips_bloqueadas = set()

class HoneypotHandler(BaseHTTPRequestHandler):

    def esta_bloqueada(self, ip):
        # Si ya está explícitamente bloqueada, devolver True inmediatamente
        if ip in ips_bloqueadas:
            return True

        # Limpiar intentos viejos fuera de la ventana
        ahora = time.time()
        intentos_por_ip[ip] = [t for t in intentos_por_ip[ip] if ahora - t < VENTANA_TIEMPO]

        if len(intentos_por_ip[ip]) >= MAX_INTENTOS:
            ips_bloqueadas.add(ip)
            return True
        return False

    def do_GET(self):
        ip = self.client_address[0]
        if self.esta_bloqueada(ip):
            self.send_response(403)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden</h1><p>IP bloqueada por multiples intentos fallidos.</p>")
            logging.warning(f"IP BLOQUEADA intento acceso: {ip}")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html = """
        <!DOCTYPE html>
        <html><head><title>Sistema Demo - Seguridad</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
            <p style="color:red; font-size:12px;">AVISO: Sistema de demostracion. Se registran IPs con fines de seguridad.</p>
            <h2>Panel de Administracion - DEMO</h2>
            <form method="POST">
                <input type="text" name="user" placeholder="Usuario" required><br><br>
                <input type="password" name="pass" placeholder="Contrasena" required><br><br>
                <button type="submit">Ingresar</button>
            </form>
        </body></html>
        """
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        ip = self.client_address[0]
        if self.esta_bloqueada(ip):
            self.send_response(403)
            self.end_headers()
            return

        try:
            # Validar Content-Type mínimo
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('application/x-www-form-urlencoded'):
                self.send_error(400, "Bad Request - unsupported Content-Type")
                logging.warning(f"Rechazado POST por Content-Type no soportado | IP: {ip} | CT: {content_type}")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_CONTENT_LENGTH:
                self.send_error(413, "Payload Too Large")
                logging.warning(f"POSIBLE DOS | IP: {ip} | Size: {content_length}")
                return

            post_data = self.rfile.read(content_length).decode('utf-8')
            datos = urllib.parse_qs(post_data)
            usuario = datos.get('user', [''])[0]
            ua = self.headers.get('User-Agent', 'Desconocido')

            # Registrar intento (no guardamos contraseñas en logs)
            intentos_por_ip[ip].append(time.time())
            intento_n = len(intentos_por_ip[ip])
            log_msg = f"INTENTO {intento_n}/{MAX_INTENTOS} | IP: {ip} | Usuario: '{usuario}' | UA: {ua}"
            logging.info(log_msg)
            print(f"[!] {log_msg}")

            if intento_n >= MAX_INTENTOS:
                logging.critical(f"IP BLOQUEADA: {ip} por exceder {MAX_INTENTOS} intentos")

        except ValueError:
            self.send_error(400, "Bad Request")
        except Exception as e:
            logging.error(f"{ip} | Error: {e}")
            self.send_error(500, "Internal Server Error")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<h3>Acceso denegado. Evento registrado.</h3><a href='/'>Volver</a>")

if __name__ == "__main__":
    try:
        print(f"[+] Honeypot PRO v3.1 corriendo en puerto {PORT}")
        print(f"[+] Bloqueo automatico tras {MAX_INTENTOS} intentos en {VENTANA_TIEMPO/60} min")
        server = ThreadingHTTPServer(("0.0.0.0", PORT), HoneypotHandler)
        server.serve_forever()
    except OSError as e:
        print(f"[ERROR] No se pudo iniciar el servidor en puerto {PORT}: {e}")
    except KeyboardInterrupt:
        print("\n[+] Servidor detenido manualmente")
