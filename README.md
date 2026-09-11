Radar Lite Honeypot

Radar Lite Honeypot es un proyecto educativo y de portafolio diseñado para demostrar habilidades en ciberseguridad, programación y arquitectura ligera.  
No pretende competir con soluciones empresariales como Palo Alto Networks, sino ofrecer un ejemplo funcional, eficiente y fácil de desplegar en entornos pequeños (ferreterías, farmacias, oficinas locales).

---

🎯 Objetivos
- Mostrar iniciativa y capacidad técnica en el desarrollo de honeypots.  
- Proveer un sistema low-resource que pueda correr en equipos modestos (PC, Raspberry Pi, Android con PyDroid).  
- Registrar intentos de acceso y bloquear IPs tras múltiples fallos.

---

⚙️ Características
- Servidor HTTP multihilo (ThreadingHTTPServer) para manejar múltiples conexiones.  
- Base de datos SQLite para registrar intentos y bloqueos.  
- Logging rotativo para evitar crecimiento descontrolado de archivos de log.  
- Bloqueo de IPs configurable tras intentos fallidos en una ventana de tiempo.  
- Credenciales parametrizadas mediante variables de entorno (no hardcodeadas).  
- Sanitización básica de inputs para reducir riesgos de inyección.  
- Panel web con estadísticas de intentos y bloqueos.

---

🚀 Instalación y uso
1. Clonar el repositorio:
   `bash
   git clone https://github.com/tuusuario/Radarlitehoneypot.git
   cd Radarlitehoneypot
   `

2. Instalar dependencias (Python 3.x):
   `bash
   pip install -r requirements.txt
   `
   (SQLite y logging ya vienen incluidos en la librería estándar de Python).

3. Configurar credenciales (opcional):
   `bash
   export HONEYPOT_USER="admin"
   export HONEYPOT_PASS="demo123"
   `

4. Ejecutar:
   `bash
   python honeypot_demo.py
   `

5. Acceder al panel:
   `
   http://localhost:8080
   `

---

📊 Ejemplo de funcionamiento
- Un atacante intenta acceder con credenciales incorrectas.  
- El sistema registra el intento en la base de datos y en el log.  
- Tras 5 intentos fallidos en 10 minutos, la IP queda bloqueada temporalmente.  
- El administrador puede ver estadísticas y últimos intentos en el panel web.

---

⚠️ Limitaciones
- No es producción: es un proyecto educativo y de demostración.  
- Bloqueo por IP puede generar falsos positivos en redes NAT.  
- Servidor básico: no escala a grandes volúmenes de tráfico.  
- Protección limitada: no sustituye firewalls ni IDS profesionales.

---

🛠️ Próximas mejoras
- Integración con dashboards externos (Grafana, Kibana).  
- Alertas en tiempo real vía correo o Telegram.  
- Mejoras en detección de patrones de ataque.  
- Opciones de despliegue en contenedores (Docker).

---

📜 Licencia
Este proyecto se distribuye bajo licencia MIT.  
Úsalo libremente para aprendizaje, portafolio y demostración.

---

👤 Autor
Osvaldo Quiñenao  
Arquitecto ético adversarial, custodio y testigo operativo de Radar Ético.  
Co-author: Copilot
