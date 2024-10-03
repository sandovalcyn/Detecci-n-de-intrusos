#Código: Detección de Intrusiones Básica mediante Análisis de Logs
python
Copiar código
import re
from collections import defaultdict

# Definir el umbral de intentos fallidos para activar una alerta
UMBRAL_INTENTOS = 5

# Simulación de archivo de logs de un servidor
logs = """
192.168.1.10 - - [01/Oct/2024:10:00:00] "GET /login HTTP/1.1" 200
192.168.1.10 - - [01/Oct/2024:10:00:05] "POST /login HTTP/1.1" 401
192.168.1.15 - - [01/Oct/2024:10:01:00] "POST /login HTTP/1.1" 401
192.168.1.15 - - [01/Oct/2024:10:01:05] "POST /login HTTP/1.1" 401
192.168.1.15 - - [01/Oct/2024:10:01:10] "POST /login HTTP/1.1" 401
192.168.1.15 - - [01/Oct/2024:10:01:15] "POST /login HTTP/1.1" 401
192.168.1.15 - - [01/Oct/2024:10:01:20] "POST /login HTTP/1.1" 401
192.168.1.20 - - [01/Oct/2024:10:02:00] "GET /index.html HTTP/1.1" 200
"""

# Expresión regular para extraer la IP y el código de respuesta del log
patron_log = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[\d+/[A-Za-z]+/\d+:\d+:\d+:\d+\] "POST /login HTTP/1.1" (\d+)')

# Diccionario para contar los intentos fallidos por IP
intentos_fallidos = defaultdict(int)

# Analizar los logs
for linea in logs.splitlines():
    coincidencia = patron_log.search(linea)
    if coincidencia:
        ip, codigo_respuesta = coincidencia.groups()
        if codigo_respuesta == '401':  # 401 indica intento fallido de autenticación
            intentos_fallidos[ip] += 1

# Detectar IPs sospechosas
print("Análisis de logs: Intentos fallidos detectados\n")
for ip, intentos in intentos_fallidos.items():
    print(f"IP: {ip}, Intentos fallidos: {intentos}")
    if intentos >= UMBRAL_INTENTOS:
        print(f"⚠️ ALERTA: Múltiples intentos fallidos detectados desde la IP {ip}.")
