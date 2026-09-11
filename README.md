# Radar Lite Honeypot

Radar Lite Honeypot es un proyecto **educativo y de portafolio** diseñado para demostrar habilidades en ciberseguridad, programación y arquitectura ligera.  
No pretende competir con soluciones empresariales como Palo Alto Networks, sino ofrecer un ejemplo funcional, eficiente y fácil de desplegar en entornos pequeños (ferreterías, farmacias, oficinas locales).

---

## 🎯 Objetivos
- Mostrar iniciativa y capacidad técnica en el desarrollo de honeypots.  
- Proveer un sistema **low-resource** que pueda correr en equipos modestos (PC, Raspberry Pi, Android con PyDroid).  
- Registrar intentos de acceso y bloquear IPs tras múltiples fallos.  

---

## ⚙️ Características
- **Servidor HTTP multihilo** (`ThreadingHTTPServer`) para manejar múltiples conexiones.  
- **Base de datos SQLite** para registrar intentos y bloqueos.  
- **Logging rotativo** para evitar crecimiento descontrolado de archivos de log.  
- **Bloqueo de IPs configurable** tras intentos fallidos en una ventana de tiempo.  
- **Credenciales parametrizadas** mediante variables de entorno (no hardcodeadas).  
- **Sanitización básica de inputs** para reducir riesgos de inyección.  
- **Panel web** con estadísticas de intentos y bloqueos.

---

## 🚀 Instalación y uso
1. Clonar el repositorio:
   ```bash
   git clone https://github.com/tuusuario/Radar_lite_honeypot.git
   cd Radar_lite_honeypot

instalar dependencias (Python 3.x)
   pip install -r requirements.txt

Configurar credenciales (opcional)
   export HONEYPOT_USER="admin"
export HONEYPOT_PASS="demo123"

ejecutar
python honeypot_demo.py

Acceder al panel:
http://localhost:8080
