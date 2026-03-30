import sys
import json
import os
import requests
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTabWidget, QLineEdit, QPushButton, 
                             QTextEdit, QLabel, QFileDialog, QMessageBox, 
                             QGroupBox, QFormLayout, QProgressBar)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont

# Importar solo si es necesario
try:
    from PyQt5.QtCore import QCoreApplication
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
except:
    pass

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
                return response.json()
        except Exception as e:
            return {"error": str(e)}
    
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
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
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
        self.setWindowTitle("ZetaVirusTotal GUI v1.0")
        self.setGeometry(200, 200, 1200, 800)
        
        # Estilo
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QLineEdit, QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QTabBar::tab {
                padding: 8px;
                margin-right: 2px;
            }
        """)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Título
        title = QLabel("ZetaVirusTotal GUI")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("padding: 10px; background-color: #e3f2fd; border-radius: 5px;")
        main_layout.addWidget(title)
        
        # Barra de estado
        self.status_label = QLabel("Iniciando...")
        self.status_label.setStyleSheet("padding: 5px; background-color: #f0f0f0; border-radius: 3px;")
        main_layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Pestañas
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Crear todas las pestañas
        tabs.addTab(self.create_upload_tab(), "📁 Subir Archivo")
        tabs.addTab(self.create_hash_tab(), "🔍 Reporte por Hash")
        tabs.addTab(self.create_url_tab(), "🌐 Analizar URL")
        tabs.addTab(self.create_url_report_tab(), "📊 Reporte URL")
        tabs.addTab(self.create_domain_tab(), "🏠 Reporte Dominio")
        tabs.addTab(self.create_ip_tab(), "🖥️ Reporte IP")
        
        # Área de resultados
        result_label = QLabel("Resultados:")
        result_label.setFont(QFont("Arial", 10, QFont.Bold))
        main_layout.addWidget(result_label)
        
        self.result_text = QTextEdit()
        self.result_text.setFont(QFont("Courier New", 9))
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("background-color: #2d2d2d; color: #f8f8f2;")
        main_layout.addWidget(self.result_text)
    
    def create_upload_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
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
        
        analyze_btn = QPushButton("🚀 Analizar Archivo")
        analyze_btn.clicked.connect(self.upload_file)
        analyze_btn.setMinimumHeight(40)
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
        
        analyze_btn = QPushButton("🌐 Analizar URL")
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
        """Cargar configuración desde archivo"""
        try:
            if os.path.exists("config.json"):
                with open("config.json", "r", encoding='utf-8') as f:
                    config = json.load(f)
                
                api_key = config.get("api_key", "")
                if api_key and api_key != "TU_API_KEY_AQUI":
                    self.api = VirusTotalAPI(api_key)
                    self.status_label.setText("✅ API conectada correctamente")
                    self.status_label.setStyleSheet("padding: 5px; background-color: #d4edda; color: #155724; border-radius: 3px;")
                else:
                    self.status_label.setText("⚠️ Configura tu API key en config.json")
                    self.status_label.setStyleSheet("padding: 5px; background-color: #fff3cd; color: #856404; border-radius: 3px;")
                    self.show_config_warning()
            else:
                self.status_label.setText("❌ Archivo config.json no encontrado")
                self.status_label.setStyleSheet("padding: 5px; background-color: #f8d7da; color: #721c24; border-radius: 3px;")
                self.create_config_template()
        except Exception as e:
            self.status_label.setText(f"❌ Error cargando configuración: {str(e)}")
            self.status_label.setStyleSheet("padding: 5px; background-color: #f8d7da; color: #721c24; border-radius: 3px;")
    
    def create_config_template(self):
        """Crear plantilla de configuración"""
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
        """Mostrar advertencia de configuración"""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Configuración requerida")
        msg.setText("Por favor, configura tu API key de VirusTotal")
        msg.setInformativeText("1. Obtén una API key en https://www.virustotal.com/gui/join-us\n"
                              "2. Edita el archivo config.json\n"
                              "3. Reemplaza 'TU_API_KEY_AQUI' con tu API key\n"
                              "4. Reinicia la aplicación")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
    
    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo para analizar")
        if file_name:
            self.file_path.setText(file_name)
    
    def start_analysis(self, operation, data):
        """Iniciar análisis en thread separado"""
        if not self.api:
            QMessageBox.warning(self, "Error", "API no configurada. Verifica tu API key en config.json")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.result_text.clear()
        self.result_text.setPlainText("⏳ Analizando, por favor espera...")
        
        self.current_thread = AnalysisThread(self.api, operation, data)
        self.current_thread.progress.connect(self.progress_bar.setValue)
        self.current_thread.finished.connect(self.on_analysis_finished)
        self.current_thread.error.connect(self.on_analysis_error)
        self.current_thread.start()
    
    def on_analysis_finished(self, result):
        """Mostrar resultados del análisis"""
        self.progress_bar.setVisible(False)
        self.result_text.clear()
        
        try:
            formatted_result = json.dumps(result, indent=2, ensure_ascii=False)
            self.result_text.setPlainText(formatted_result)
            
            # Si hay error en el resultado de la API
            if "error" in result:
                self.status_label.setText(f"❌ Error en API: {result['error']}")
                self.status_label.setStyleSheet("padding: 5px; background-color: #f8d7da; color: #721c24; border-radius: 3px;")
            else:
                self.status_label.setText("✅ Análisis completado exitosamente")
                self.status_label.setStyleSheet("padding: 5px; background-color: #d4edda; color: #155724; border-radius: 3px;")
        except Exception as e:
            self.result_text.setPlainText(f"Error formateando resultado: {str(e)}\n\nResultado original:\n{result}")
    
    def on_analysis_error(self, error_msg):
        """Manejar errores del thread"""
        self.progress_bar.setVisible(False)
        self.result_text.clear()
        self.result_text.setPlainText(f"❌ Error en el análisis:\n{error_msg}")
        self.status_label.setText(f"❌ Error: {error_msg}")
        self.status_label.setStyleSheet("padding: 5px; background-color: #f8d7da; color: #721c24; border-radius: 3px;")
    
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
        app.setStyle('Fusion')  # Estilo moderno
        
        # Verificar que la aplicación se crea correctamente
        window = VirusTotalGUI()
        window.show()
        
        # Forzar que la ventana se muestre al frente
        window.raise_()
        window.activateWindow()
        
        print("Aplicación iniciada correctamente")
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error crítico: {e}")
        import traceback
        traceback.print_exc()
        input("Presiona Enter para salir...")

if __name__ == "__main__":
    main()