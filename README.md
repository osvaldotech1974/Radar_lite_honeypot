# Honeypot Demo - Detección de Intrusos

Sistema educativo en Python que simula un panel de login para registrar intentos de acceso.

## Features v3
- Bloqueo automático de IP tras 5 intentos fallidos en 10 minutos
- Respuesta HTTP 403 para IPs bloqueadas
- Logging estructurado para análisis
- Protección básica Anti-DoS por Content-Length
  
## Uso
Solo para fines educativos y de laboratorio.
```bash
python honeypot_demo.py
