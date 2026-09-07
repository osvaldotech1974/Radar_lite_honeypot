from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse # <- aqui
import datetime
import os

PORT = 8080
LOG_FILE = "intentos_acceso.log"

class HoneypotHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html = """... el mismo html con el AVISO..."""
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            datos = urllib.parse.parse_qs(post_data) # <- corregido

            usuario = datos.get('user', [''])[0]
            ip = self.client_address[0]
            ua = self.headers.get('User-Agent', 'Desconocido')
            hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            linea = f"[{hora}] IP: {ip} | Usuario Probado: '{usuario}' | UA: {ua}\n"
            print(f"[!] Intento detectado: {linea.strip()}")

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(linea)
        except Exception as e:
            print(f"[ERROR] {e}")

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<h3>Acceso denegado. Evento registrado.</h3><a href='/'>Volver</a>")

if __name__ == "__main__":
    print(f"[+] Honeypot DEMO corriendo en puerto {PORT}")
    server = HTTPServer(("0.0.0.0", PORT), HoneypotHandler)
    server.serve_forever()
