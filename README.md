# zetaVirusTotalGui
Una herramienta de escritorio con interfaz gráfica intuitiva para interactuar con la API de VirusTotal. Permite analizar archivos, URLs, dominios y direcciones IP utilizando más de 70 motores antivirus y herramientas de seguridad.
## ✨ Características

- 📁 **Análisis de archivos**: Sube y analiza archivos con +70 antivirus
- 🔍 **Reporte por hash**: Consulta resultados usando MD5, SHA1 o SHA256
- 🌐 **Análisis de URLs**: Envía URLs para escaneo en tiempo real
- 📊 **Reporte de URLs**: Obtén análisis detallados de URLs específicas
- 🏠 **Reporte de dominios**: Consulta reputación y análisis de dominios
- 🖥️ **Reporte de IPs**: Verifica reputación de direcciones IP
- ⚡ **Análisis asíncrono**: Interfaz no bloqueante con barra de progreso
- 🎨 **Interfaz moderna**: Diseño limpio y fácil de usar
- 📋 **Resultados formateados**: Visualización JSON con colores y estructura

## 🚀 Endpoints de VirusTotal Utilizados

La herramienta implementa los siguientes endpoints de la API v3 de VirusTotal:

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/files` | POST | Sube un archivo para análisis |
| `/files/{hash}` | GET | Obtiene reporte por hash (MD5/SHA1/SHA256) |
| `/urls` | POST | Analiza una URL |
| `/urls/{id}` | GET | Obtiene reporte de una URL |
| `/domains/{domain}` | GET | Obtiene reporte de un dominio |
| `/ip_addresses/{ip}` | GET | Obtiene reporte de una dirección IP |

## 📋 Requisitos Previos

- Python 3.7 o superior
- API Key de VirusTotal (obténla gratis en [VirusTotal](https://www.virustotal.com/gui/join-us))

## 🔧 Instalación

1. **Clona el repositorio**
   ```bash
   git clone https://github.com/LuisAZambrana/zetaVirusTotalGui.git
   cd zetaVirusTotalGui
2. **Instala las dependencias**
   ```bash
   pip install -r requirements.txt
3. **Tu api key en config.json**
4. **Ejecutár y usar**
   ```bash
   python virus_total_gui.py

Si lo usas en windows puede que tengas que ejecutarlo con algun comando especifico de la version que tengas instalada de python como:
   ```bash
   py -3.13 virus_total_gui.py

Visitanos en https://luiszambrana.ar
