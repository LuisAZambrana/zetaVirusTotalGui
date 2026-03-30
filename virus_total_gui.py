import sys
import json
import os
import requests
import time
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTabWidget, QLineEdit, QPushButton, 
                             QTextEdit, QLabel, QFileDialog, QMessageBox, 
                             QGroupBox, QFormLayout, QProgressBar, QSplitter,
                             QFrame, QGridLayout)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QColor, QTextCursor, QPalette

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "accept": "application/json"
        }
    
    def upload_file(self, file_path):
        """Subir archivo para análisis"""
        url = f"{self.base_url}/files"
        try:
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = requests.post(url, headers=self.headers, files=files, timeout=30)
                result = response.json()
                
                # Si la subida fue exitosa, obtener el ID del análisis y esperar resultados
                if "data" in result and "id" in result["data"]:
                    analysis_id = result["data"]["id"]
                    return self._wait_for_analysis(analysis_id)
                return result
        except Exception as e:
            return {"error": str(e)}
    
    def _wait_for_analysis(self, analysis_id, max_wait=60):
        """Esperar a que el análisis se complete"""
        url = f"{self.base_url}/analyses/{analysis_id}"
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                response = requests.get(url, headers=self.headers, timeout=30)
                result = response.json()
                
                if "data" in result and "attributes" in result["data"]:
                    status = result["data"]["attributes"].get("status", "")
                    if status == "completed":
                        # Obtener el hash del archivo para el reporte completo
                        if "meta" in result and "file_info" in result["meta"]:
                            file_hash = result["meta"]["file_info"].get("sha256")
                            if file_hash:
                                return self.get_file_report(file_hash)
                        return result
                    elif status == "queued":
                        time.sleep(3)  # Esperar 3 segundos antes de reintentar
                        continue
                
                time.sleep(1)
            except Exception as e:
                return {"error": f"Error esperando análisis: {str(e)}"}
        
        return {"error": "Timeout esperando resultados del análisis"}
    
    def get_file_report(self, file_hash):
        """Obtener reporte por hash"""
        url = f"{self.base_url}/files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def scan_url(self, url):
        """Analizar URL"""
        scan_url = f"{self.base_url}/urls"
        data = {"url": url}
        try:
            response = requests.post(scan_url, headers=self.headers, data=data, timeout=30)
            result = response.json()
            
            if "data" in result and "id" in result["data"]:
                analysis_id = result["data"]["id"]
                return self._wait_for_url_analysis(analysis_id, url)
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def _wait_for_url_analysis(self, analysis_id, url, max_wait=30):
        """Esperar a que el análisis de URL se complete"""
        url_endpoint = f"{self.base_url}/analyses/{analysis_id}"
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                response = requests.get(url_endpoint, headers=self.headers, timeout=30)
                result = response.json()
                
                if "data" in result and "attributes" in result["data"]:
                    status = result["data"]["attributes"].get("status", "")
                    if status == "completed":
                        return self.get_url_report(url)
                    elif status == "queued":
                        time.sleep(2)
                        continue
                
                time.sleep(1)
            except Exception as e:
                return {"error": f"Error esperando análisis: {str(e)}"}
        
        return {"error": "Timeout esperando resultados del análisis"}
    
    def get_url_report(self, url):
        """Obtener reporte de URL"""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"{self.base_url}/urls/{url_id}"
        try:
            response = requests.get(report_url, headers=self.headers, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_domain_report(self, domain):
        """Obtener reporte de dominio"""
        url = f"{self.base_url}/domains/{domain}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_ip_report(self, ip):
        """Obtener reporte de IP"""
        url = f"{self.base_url}/ip_addresses/{ip}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

class ResultFormatter:
    """Clase para formatear resultados de manera legible"""
    
    @staticmethod
    def format_file_report(data):
        """Formatear reporte de archivo - Versión mejorada"""
        if "error" in data:
            return ResultFormatter._format_error(data['error'])
        
        if "data" not in data:
            return "❌ No se encontraron datos en la respuesta"
        
        attributes = data["data"].get("attributes", {})
        
        output = []
        output.append("=" * 90)
        output.append("📁 REPORTE COMPLETO DE ANÁLISIS DE ARCHIVO")
        output.append("=" * 90)
        
        # Información básica del archivo
        output.append("\n📋 INFORMACIÓN DEL ARCHIVO:")
        output.append(f"  • Nombre: {attributes.get('meaningful_name', 'N/A')}")
        output.append(f"  • Tamaño: {ResultFormatter._format_size(attributes.get('size', 0))}")
        output.append(f"  • Tipo: {attributes.get('type_description', 'N/A')}")
        output.append(f"  • Tipo MIME: {attributes.get('type_tag', 'N/A')}")
        
        # Hashes
        output.append("\n🔐 HASHES DEL ARCHIVO:")
        output.append(f"  • MD5: {attributes.get('md5', 'N/A')}")
        output.append(f"  • SHA1: {attributes.get('sha1', 'N/A')}")
        output.append(f"  • SHA256: {attributes.get('sha256', 'N/A')}")
        
        # Estadísticas de detección
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        type_unsupported = stats.get('type-unsupported', 0)
        
        total_engines = malicious + suspicious + undetected + harmless + type_unsupported
        
        output.append("\n🛡️ ESTADÍSTICAS DE DETECCIÓN:")
        output.append(f"  • 🟢 LIMPIO: {undetected} motores")
        output.append(f"  • 🟡 SOSPECHOSO: {suspicious} motores")
        output.append(f"  • 🔴 MALICIOSO: {malicious} motores")
        output.append(f"  • ⚪ INOCUO: {harmless} motores")
        output.append(f"  • 📄 TIPO NO SOPORTADO: {type_unsupported} motores")
        output.append(f"  • 📊 TOTAL MOTORES: {total_engines}")
        
        # Nivel de riesgo con emoji
        risk_level, risk_emoji, risk_color = ResultFormatter._get_risk_level_detailed(malicious, suspicious)
        output.append(f"\n⚠️ NIVEL DE RIESGO: {risk_emoji} {risk_level}")
        
        # Resumen ejecutivo
        output.append("\n📊 RESUMEN EJECUTIVO:")
        if malicious == 0 and suspicious == 0:
            output.append("  ✅ EL ARCHIVO PARECE SER SEGURO")
            output.append("  ✓ Ningún antivirus detectó amenazas")
            output.append("  ✓ El archivo pasó todas las pruebas de seguridad")
        elif malicious > 0:
            output.append(f"  🔴 ¡ALERTA! {malicious} antivirus detectaron malware")
            output.append(f"  ⚠️ No ejecutes este archivo sin verificar")
            output.append(f"  🔍 Revisa los detalles de detección a continuación")
        elif suspicious > 0:
            output.append(f"  🟡 PRECAUCIÓN: {suspicious} antivirus marcaron como sospechoso")
            output.append(f"  ℹ️ El archivo puede ser seguro pero requiere verificación")
        
        # Detalles de detecciones (solo si hay alguna)
        results = attributes.get('last_analysis_results', {})
        if results and (malicious > 0 or suspicious > 0):
            output.append("\n🔍 DETALLES DE DETECCIONES:")
            
            if malicious > 0:
                output.append("\n  🚨 DETECTADO COMO MALICIOSO:")
                count = 0
                for engine, result in results.items():
                    if result.get('category') == 'malicious' and count < 15:
                        detection = result.get('result', 'Malware detectado')
                        output.append(f"    • {engine}: {detection}")
                        count += 1
                if count < malicious:
                    output.append(f"    ... y {malicious - count} motores más")
            
            if suspicious > 0:
                output.append("\n  ⚠️ MARCADO COMO SOSPECHOSO:")
                count = 0
                for engine, result in results.items():
                    if result.get('category') == 'suspicious' and count < 10:
                        detection = result.get('result', 'Sospechoso')
                        output.append(f"    • {engine}: {detection}")
                        count += 1
                if count < suspicious:
                    output.append(f"    ... y {suspicious - count} motores más")
        
        # Etiquetas y comportamiento
        tags = attributes.get('tags', [])
        if tags:
            output.append(f"\n🏷️ ETIQUETAS DETECTADAS:")
            for tag in tags[:10]:
                output.append(f"  • {tag}")
        
        # Información de reputación
        reputation = attributes.get('reputation', 0)
        if reputation != 0:
            output.append(f"\n⭐ REPUTACIÓN: {reputation}")
        
        # Último análisis
        last_analysis_date = attributes.get('last_analysis_date', 0)
        if last_analysis_date:
            date_str = datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
            output.append(f"\n🕒 ÚLTIMO ANÁLISIS: {date_str}")
        
        # Información adicional
        if 'crowdsourced_ids_stats' in attributes:
            ids_stats = attributes['crowdsourced_ids_stats']
            if ids_stats:
                output.append(f"\n🛡️ DETECCIÓN IDS/IPS:")
                output.append(f"  • Alto: {ids_stats.get('high', 0)}")
                output.append(f"  • Medio: {ids_stats.get('medium', 0)}")
                output.append(f"  • Bajo: {ids_stats.get('low', 0)}")
        
        output.append("\n" + "=" * 90)
        return "\n".join(output)
    
    @staticmethod
    def format_url_report(data, url):
        """Formatear reporte de URL"""
        if "error" in data:
            return ResultFormatter._format_error(data['error'])
        
        if "data" not in data:
            return "❌ No se encontraron datos en la respuesta"
        
        attributes = data["data"].get("attributes", {})
        
        output = []
        output.append("=" * 90)
        output.append("🌐 REPORTE DE URL")
        output.append("=" * 90)
        output.append(f"\n🔗 URL ANALIZADA: {url}")
        
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        output.append("\n📊 ESTADÍSTICAS:")
        output.append(f"  • Maliciosa: {malicious}")
        output.append(f"  • Sospechosa: {suspicious}")
        output.append(f"  • Limpia: {stats.get('undetected', 0)}")
        
        risk_level, risk_emoji, _ = ResultFormatter._get_risk_level_detailed(malicious, suspicious)
        output.append(f"  • Nivel de riesgo: {risk_emoji} {risk_level}")
        
        if malicious == 0 and suspicious == 0:
            output.append("\n✅ LA URL PARECE SER SEGURA")
        elif malicious > 0:
            output.append(f"\n🔴 ¡ALERTA! {malicious} servicios de seguridad bloquean esta URL")
            
            # Mostrar detalles de bloqueo
            results = attributes.get('last_analysis_results', {})
            output.append("\n🚫 BLOQUEADA POR:")
            count = 0
            for engine, result in results.items():
                if result.get('category') == 'malicious' and count < 15:
                    output.append(f"  • {engine}: {result.get('result', 'Bloqueada')}")
                    count += 1
        
        output.append("\n" + "=" * 90)
        return "\n".join(output)
    
    @staticmethod
    def format_domain_report(data, domain):
        """Formatear reporte de dominio"""
        if "error" in data:
            return ResultFormatter._format_error(data['error'])
        
        if "data" not in data:
            return "❌ No se encontraron datos en la respuesta"
        
        attributes = data["data"].get("attributes", {})
        
        output = []
        output.append("=" * 90)
        output.append("🏠 REPORTE DE DOMINIO")
        output.append("=" * 90)
        output.append(f"\n🌐 Dominio: {domain}")
        
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        
        output.append("\n📊 ESTADÍSTICAS:")
        output.append(f"  • Malicioso: {malicious}")
        output.append(f"  • Sospechoso: {stats.get('suspicious', 0)}")
        output.append(f"  • Limpio: {stats.get('undetected', 0)}")
        
        if malicious == 0:
            output.append("\n✅ DOMINIO SIN DETECCIONES MALICIOSAS")
        else:
            output.append(f"\n🔴 ¡ALERTA! {malicious} servicios bloquean este dominio")
        
        # Categorías
        categories = attributes.get('categories', {})
        if categories:
            output.append("\n📁 CATEGORÍAS ASIGNADAS:")
            for source, category in list(categories.items())[:5]:
                output.append(f"  • {source}: {category}")
        
        output.append("\n" + "=" * 90)
        return "\n".join(output)
    
    @staticmethod
    def format_ip_report(data, ip):
        """Formatear reporte de IP"""
        if "error" in data:
            return ResultFormatter._format_error(data['error'])
        
        if "data" not in data:
            return "❌ No se encontraron datos en la respuesta"
        
        attributes = data["data"].get("attributes", {})
        
        output = []
        output.append("=" * 90)
        output.append("🖥️ REPORTE DE DIRECCIÓN IP")
        output.append("=" * 90)
        output.append(f"\n🌐 IP: {ip}")
        
        # País
        country = attributes.get('country', 'Desconocido')
        output.append(f"📍 Ubicación: {country}")
        
        # ASN
        as_owner = attributes.get('as_owner', '')
        asn = attributes.get('asn', '')
        if as_owner or asn:
            output.append(f"🏢 Proveedor: {as_owner} (AS{asn})" if asn else f"🏢 Proveedor: {as_owner}")
        
        # Estadísticas
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        
        output.append("\n📊 ESTADÍSTICAS DE SEGURIDAD:")
        output.append(f"  • Maliciosa: {malicious}")
        output.append(f"  • Sospechosa: {stats.get('suspicious', 0)}")
        output.append(f"  • Limpia: {stats.get('undetected', 0)}")
        
        if malicious == 0:
            output.append("\n✅ IP SIN DETECCIONES MALICIOSAS")
        else:
            output.append(f"\n🔴 ¡ALERTA! {malicious} servicios de seguridad reportan esta IP como maliciosa")
        
        # Reputación
        reputation = attributes.get('reputation', 0)
        if reputation != 0:
            output.append(f"\n⭐ Reputación: {reputation}")
        
        output.append("\n" + "=" * 90)
        return "\n".join(output)
    
    @staticmethod
    def _format_size(bytes_size):
        """Formatear tamaño de archivo"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"
    
    @staticmethod
    def _get_risk_level_detailed(malicious, suspicious):
        """Determinar nivel de riesgo detallado"""
        if malicious == 0 and suspicious == 0:
            return "BAJO (Seguro)", "✅", "green"
        elif malicious == 0 and suspicious > 0:
            return f"MEDIO ({suspicious} detecciones sospechosas)", "⚠️", "yellow"
        elif malicious <= 3:
            return f"ALTO ({malicious} detecciones maliciosas)", "🔴", "red"
        else:
            return f"CRÍTICO ({malicious} detecciones maliciosas)", "💀", "darkred"
    
    @staticmethod
    def _format_error(error_msg):
        """Formatear mensaje de error"""
        return f"""
{'=' * 90}
❌ ERROR EN EL ANÁLISIS
{'=' * 90}

{error_msg}

Posibles causas:
• API key inválida o expirada
• Límite de solicitudes excedido
• Problema de conexión a internet
• El recurso no existe o no es accesible

{'=' * 90}
"""

class AnalysisThread(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)
    
    def __init__(self, api, operation, data):
        super().__init__()
        self.api = api
        self.operation = operation
        self.data = data
    
    def run(self):
        try:
            self.progress.emit(50)
            
            if self.operation == "upload_file":
                result = self.api.upload_file(self.data)
            elif self.operation == "file_report":
                result = self.api.get_file_report(self.data)
            elif self.operation == "scan_url":
                result = self.api.scan_url(self.data)
            elif self.operation == "url_report":
                result = self.api.get_url_report(self.data)
            elif self.operation == "domain_report":
                result = self.api.get_domain_report(self.data)
            elif self.operation == "ip_report":
                result = self.api.get_ip_report(self.data)
            else:
                result = {"error": "Operación no válida"}
            
            self.progress.emit(100)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class VirusTotalGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.api = None
        self.current_thread = None
        self.init_ui()
        self.load_config()
    
    def init_ui(self):
        self.setWindowTitle("ZetaVirusTotalGui v1")
        self.setGeometry(100, 100, 1400, 1000)
        
        # Estilo mejorado
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QPushButton {
                background-color: #0f3460;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #16213e;
            }
            QLineEdit, QTextEdit {
                border: 1px solid #0f3460;
                border-radius: 8px;
                padding: 8px;
                background-color: #16213e;
                color: #e94560;
                font-family: 'Courier New';
            }
            QTabWidget::pane {
                border: 1px solid #0f3460;
                border-radius: 8px;
                background-color: #16213e;
            }
            QTabBar::tab {
                padding: 10px 20px;
                background-color: #0f3460;
                color: white;
            }
            QTabBar::tab:selected {
                background-color: #e94560;
                color: white;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #0f3460;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                color: #e94560;
            }
            QLabel {
                color: white;
            }
        """)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Título
        title = QLabel("🛡️ ZetaVirusTotalGUI v1 - Análisis Inteligente de Seguridad")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("padding: 15px; background-color: #2986CC; color: white; border-radius: 10px; margin-bottom: 10px;")
        main_layout.addWidget(title)
        
        # Barra de estado
        self.status_label = QLabel("🟢 Iniciando...")
        self.status_label.setStyleSheet("padding: 8px; background-color: #16213e; border-radius: 8px; color: #e94560;")
        main_layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #e94560; }")
        main_layout.addWidget(self.progress_bar)
        
        # Splitter para resultados
        splitter = QSplitter(Qt.Vertical)
        
        # Pestañas
        tabs = QTabWidget()
        tabs.setMinimumHeight(350)
        
        tabs.addTab(self.create_upload_tab(), "📁 Subir Archivo")
        tabs.addTab(self.create_hash_tab(), "🔍 Reporte por Hash")
        tabs.addTab(self.create_url_tab(), "🌐 Analizar URL")
        tabs.addTab(self.create_url_report_tab(), "📊 Reporte URL")
        tabs.addTab(self.create_domain_tab(), "🏠 Reporte Dominio")
        tabs.addTab(self.create_ip_tab(), "🖥️ Reporte IP")
        
        splitter.addWidget(tabs)
        
        # Área de resultados mejorada
        result_label = QLabel("📋 RESULTADOS DEL ANÁLISIS:")
        result_label.setFont(QFont("Arial", 11, QFont.Bold))
        result_label.setStyleSheet("padding: 8px; margin-top: 10px; color: #ffffff;")
        main_layout.addWidget(result_label)
        
        self.result_text = QTextEdit()
        self.result_text.setFont(QFont("Courier New", 10))
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0f;
                color: #d4d4d4;
                border: 2px solid #e94560;
                border-radius: 10px;
                font-family: 'Courier New';
                font-size: 11px;
                line-height: 1.4;
            }
        """)
        splitter.addWidget(self.result_text)
        
        splitter.setSizes([400, 600])
        main_layout.addWidget(splitter)
    
    def create_upload_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        info_label = QLabel("ℹ️ Los archivos se analizarán automáticamente. Espera unos segundos para los resultados completos.")
        info_label.setStyleSheet("color: #2986cc; padding: 5px; background-color: #16213e; border-radius: 5px;")
        layout.addWidget(info_label)
        
        file_group = QGroupBox("Seleccionar Archivo")
        file_layout = QHBoxLayout()
        
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        self.file_path.setPlaceholderText("No se ha seleccionado ningún archivo...")
        file_layout.addWidget(self.file_path)
        
        browse_btn = QPushButton("📂 Examinar")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        analyze_btn = QPushButton("🚀 Analizar Archivo (Automático)")
        analyze_btn.clicked.connect(self.upload_file)
        analyze_btn.setMinimumHeight(45)
        analyze_btn.setStyleSheet("font-size: 14px;")
        layout.addWidget(analyze_btn)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_hash_tab(self):
        widget = QWidget()
        layout = QFormLayout()
        
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Ej: 44d88612fea8a8f36de82e1278abb02f")
        self.hash_input.setMinimumHeight(35)
        layout.addRow("Hash (MD5/SHA1/SHA256):", self.hash_input)
        
        analyze_btn = QPushButton("🔍 Obtener Reporte")
        analyze_btn.clicked.connect(self.get_file_report)
        analyze_btn.setMinimumHeight(40)
        layout.addRow(analyze_btn)
        
        widget.setLayout(layout)
        return widget
    
    def create_url_tab(self):
        widget = QWidget()
        layout = QFormLayout()
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Ej: https://example.com")
        self.url_input.setMinimumHeight(35)
        layout.addRow("URL a analizar:", self.url_input)
        
        analyze_btn = QPushButton("🌐 Analizar URL (Automático)")
        analyze_btn.clicked.connect(self.scan_url)
        analyze_btn.setMinimumHeight(40)
        layout.addRow(analyze_btn)
        
        widget.setLayout(layout)
        return widget
    
    def create_url_report_tab(self):
        widget = QWidget()
        layout = QFormLayout()
        
        self.url_report_input = QLineEdit()
        self.url_report_input.setPlaceholderText("Ej: https://example.com")
        self.url_report_input.setMinimumHeight(35)
        layout.addRow("URL:", self.url_report_input)
        
        analyze_btn = QPushButton("📊 Obtener Reporte")
        analyze_btn.clicked.connect(self.get_url_report)
        analyze_btn.setMinimumHeight(40)
        layout.addRow(analyze_btn)
        
        widget.setLayout(layout)
        return widget
    
    def create_domain_tab(self):
        widget = QWidget()
        layout = QFormLayout()
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Ej: example.com")
        self.domain_input.setMinimumHeight(35)
        layout.addRow("Dominio:", self.domain_input)
        
        analyze_btn = QPushButton("🏠 Obtener Reporte")
        analyze_btn.clicked.connect(self.get_domain_report)
        analyze_btn.setMinimumHeight(40)
        layout.addRow(analyze_btn)
        
        widget.setLayout(layout)
        return widget
    
    def create_ip_tab(self):
        widget = QWidget()
        layout = QFormLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Ej: 8.8.8.8")
        self.ip_input.setMinimumHeight(35)
        layout.addRow("Dirección IP:", self.ip_input)
        
        analyze_btn = QPushButton("🖥️ Obtener Reporte")
        analyze_btn.clicked.connect(self.get_ip_report)
        analyze_btn.setMinimumHeight(40)
        layout.addRow(analyze_btn)
        
        widget.setLayout(layout)
        return widget
    
    def load_config(self):
        try:
            if os.path.exists("config.json"):
                with open("config.json", "r", encoding='utf-8') as f:
                    config = json.load(f)
                
                api_key = config.get("api_key", "")
                if api_key and api_key != "TU_API_KEY_AQUI":
                    self.api = VirusTotalAPI(api_key)
                    self.status_label.setText("✅ API conectada correctamente - Listo para analizar")
                    self.status_label.setStyleSheet("padding: 8px; background-color: #16213e; color: #4caf50; border-radius: 8px;")
                else:
                    self.status_label.setText("⚠️ Configura tu API key en config.json")
                    self.show_config_warning()
            else:
                self.status_label.setText("❌ Archivo config.json no encontrado")
                self.create_config_template()
        except Exception as e:
            self.status_label.setText(f"❌ Error cargando configuración: {str(e)}")
    
    def create_config_template(self):
        config = {
            "api_key": "TU_API_KEY_AQUI",
            "base_url": "https://www.virustotal.com/api/v3"
        }
        try:
            with open("config.json", "w", encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            self.status_label.setText("📝 Plantilla config.json creada. Edita con tu API key y reinicia.")
        except Exception as e:
            pass
    
    def show_config_warning(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Configuración requerida")
        msg.setText("⚠️ Configuración de API Key requerida")
        msg.setInformativeText(
            "Para usar esta herramienta necesitas una API key de VirusTotal.\n\n"
            "1. Obtén una API key gratuita en: https://www.virustotal.com/gui/join-us\n"
            "2. Abre el archivo 'config.json'\n"
            "3. Reemplaza 'TU_API_KEY_AQUI' con tu API key\n"
            "4. Guarda el archivo y reinicia la aplicación\n\n"
            "✨ Novedades de la versión 3.0:\n"
            "• Resultados extremadamente detallados y legibles\n"
            "• Resumen ejecutivo con recomendaciones claras\n"
            "• Detalles completos de cada motor antivirus\n"
            "• Nivel de riesgo con colores y emojis\n"
            "• Información de reputación y etiquetas\n"
            "• Última fecha de análisis\n"
            "• Estadísticas IDS/IPS cuando disponibles"
        )
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
    
    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo para analizar")
        if file_name:
            self.file_path.setText(file_name)
    
    def start_analysis(self, operation, data, display_name=""):
        if not self.api:
            QMessageBox.warning(self, "Error", "API no configurada. Verifica tu API key en config.json")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.result_text.clear()
        self.result_text.setPlainText("⏳ Analizando... Por favor espera. Esto puede tomar varios segundos...\n\n"
                                      "El análisis incluye:\n"
                                      "• Escaneo con +70 antivirus\n"
                                      "• Análisis de comportamiento\n"
                                      "• Verificación de reputación\n"
                                      "• Detección de amenazas\n\n"
                                      "🔄 Procesando...")
        
        self.current_thread = AnalysisThread(self.api, operation, data)
        self.current_thread.progress.connect(self.progress_bar.setValue)
        self.current_thread.finished.connect(self.on_analysis_finished)
        self.current_thread.error.connect(self.on_analysis_error)
        self.current_thread.start()
    
    def on_analysis_finished(self, result):
        self.progress_bar.setVisible(False)
        self.result_text.clear()
        
        # Determinar qué tipo de operación fue y formatear resultado
        formatted_text = self.format_result(result)
        self.result_text.setPlainText(formatted_text)
        
        if "error" in result:
            self.status_label.setText("❌ Error en el análisis")
            self.status_label.setStyleSheet("padding: 8px; background-color: #16213e; color: #dc3545; border-radius: 8px;")
        else:
            self.status_label.setText("✅ Análisis completado exitosamente")
            self.status_label.setStyleSheet("padding: 8px; background-color: #16213e; color: #4caf50; border-radius: 8px;")
    
    def format_result(self, result):
        """Formatear resultado según el tipo de operación"""
        if "error" in result:
            return ResultFormatter._format_error(result['error'])
        
        # Detectar tipo de resultado basado en la estructura
        if "data" in result:
            attributes = result["data"].get("attributes", {})
            
            # Es un archivo
            if "type_description" in attributes or "md5" in attributes:
                return ResultFormatter.format_file_report(result)
            # Es una URL
            elif "url" in attributes or "categories" in attributes:
                return ResultFormatter.format_url_report(result, self.get_current_url())
            # Es un dominio
            elif "subdomains" in attributes:
                return ResultFormatter.format_domain_report(result, self.get_current_domain())
            # Es una IP
            elif "as_owner" in attributes or "country" in attributes:
                return ResultFormatter.format_ip_report(result, self.get_current_ip())
        
        # Si no se puede determinar, mostrar JSON formateado
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    def get_current_url(self):
        if hasattr(self, 'url_report_input'):
            return self.url_report_input.text()
        return ""
    
    def get_current_domain(self):
        if hasattr(self, 'domain_input'):
            return self.domain_input.text()
        return ""
    
    def get_current_ip(self):
        if hasattr(self, 'ip_input'):
            return self.ip_input.text()
        return ""
    
    def on_analysis_error(self, error_msg):
        self.progress_bar.setVisible(False)
        self.result_text.clear()
        self.result_text.setPlainText(ResultFormatter._format_error(error_msg))
        self.status_label.setText(f"❌ Error: {error_msg[:50]}...")
    
    def upload_file(self):
        if not self.file_path.text():
            QMessageBox.warning(self, "Error", "Selecciona un archivo primero")
            return
        if not os.path.exists(self.file_path.text()):
            QMessageBox.warning(self, "Error", "El archivo no existe")
            return
        self.start_analysis("upload_file", self.file_path.text())
    
    def get_file_report(self):
        if not self.hash_input.text().strip():
            QMessageBox.warning(self, "Error", "Ingresa un hash")
            return
        self.start_analysis("file_report", self.hash_input.text().strip())
    
    def scan_url(self):
        if not self.url_input.text().strip():
            QMessageBox.warning(self, "Error", "Ingresa una URL")
            return
        self.start_analysis("scan_url", self.url_input.text().strip())
    
    def get_url_report(self):
        if not self.url_report_input.text().strip():
            QMessageBox.warning(self, "Error", "Ingresa una URL")
            return
        self.start_analysis("url_report", self.url_report_input.text().strip())
    
    def get_domain_report(self):
        if not self.domain_input.text().strip():
            QMessageBox.warning(self, "Error", "Ingresa un dominio")
            return
        self.start_analysis("domain_report", self.domain_input.text().strip())
    
    def get_ip_report(self):
        if not self.ip_input.text().strip():
            QMessageBox.warning(self, "Error", "Ingresa una dirección IP")
            return
        self.start_analysis("ip_report", self.ip_input.text().strip())

def main():
    try:
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        
        window = VirusTotalGUI()
        window.show()
        window.raise_()
        window.activateWindow()
        
        print("✅ ZetaVirusTotalGUI v1 iniciado correctamente")
        print("Características:")
        print("  • Resultados detallados y legibles")
        print("  • Análisis automático con espera")
        print("  • Información completa de cada motor antivirus")
        print("  • Niveles de riesgo con emojis")
        print("  • Resumen ejecutivo con recomendaciones")
        sys.exit(app.exec_())
    except Exception as e:
        print(f"❌ Error crítico: {e}")
        import traceback
        traceback.print_exc()
        input("Presiona Enter para salir...")

if __name__ == "__main__":
    main()
