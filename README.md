# Honeypot Demo - Detección de Intrusos

Sistema educativo en Python que simula un panel de login para registrar intentos de acceso.

Feat: v4 Persistencia con SQLite + Threading + Rotacion de logs

- Agregada base de datos SQLite para guardar intentos e IPs bloqueadas
- Migracion a ThreadingHTTPServer para concurrencia
- Rotacion de logs de 5MB con 5 backups
- Validacion de Content-Type en POST

## Uso
Solo para fines educativos y de laboratorio.
```bash
python honeypot_demo.py
