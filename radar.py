import socket
import datetime
import threading

HOST = "0.0.0.0" # Escucha en todas las interfaces
PORT = 2222 # Puerto falso tipo SSH para atraer escaneos
LOG_FILE = "ataques.log"

def log_ataque(ip, puerto):
    hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{hora}] Intento de conexión desde IP: {ip} al puerto: {puerto}\n"
    print(linea.strip())
    with open(LOG_FILE, "a") as f:
        f.write(linea)

def manejar_cliente(conn, addr):
    ip = addr[0]
    log_ataque(ip, PORT)
    # Fingimos ser un servidor SSH
    conn.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n")
    conn.close()

def iniciar_radar():
    print(f"[+] Radar LITE iniciado en {HOST}:{PORT}")
    print(f"[+] Esperando atacantes... Los logs se guardan en {LOG_FILE}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=manejar_cliente, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    try:
        iniciar_radar()
    except KeyboardInterrupt:
        print("\n[-] Radar detenido")
