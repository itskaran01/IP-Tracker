import requests
import socket
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class IPTrackerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP Location Tracker")
        self.setGeometry(100, 100, 600, 500)
        
        # Main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        main_widget.setLayout(layout)
        
        # Title
        title = QLabel("IP Address Tracker")
        title.setFont(QFont('Arial', 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Input section
        input_layout = QHBoxLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address or domain")
        input_layout.addWidget(self.ip_input)
        
        track_btn = QPushButton("Track")
        track_btn.clicked.connect(self.track_ip)
        input_layout.addWidget(track_btn)
        
        myip_btn = QPushButton("My IP")
        myip_btn.clicked.connect(self.get_my_ip)
        input_layout.addWidget(myip_btn)
        
        layout.addLayout(input_layout)
        
        # Results display
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.results_table)
        
        # Raw JSON display
        self.raw_output = QTextEdit()
        self.raw_output.setReadOnly(True)
        self.raw_output.setPlaceholderText("Raw API response will appear here")
        layout.addWidget(self.raw_output)
        
        # Status bar
        self.status_bar = QLabel()
        self.status_bar.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_bar)
        
        # Initialize
        self.clear_results()
    
    def clear_results(self):
        self.results_table.setRowCount(0)
        self.raw_output.clear()
        self.status_bar.setText("Ready")
    
    def get_my_ip(self):
        try:
            # Get public IP
            response = requests.get('https://api.ipify.org?format=json')
            ip = response.json()['ip']
            self.ip_input.setText(ip)
            self.track_ip()
        except Exception as e:
            self.status_bar.setText(f"Error getting your IP: {str(e)}")
    
    def track_ip(self):
        ip_or_domain = self.ip_input.text().strip()
        if not ip_or_domain:
            self.status_bar.setText("Please enter an IP or domain")
            return
        
        self.clear_results()
        self.status_bar.setText("Tracking...")
        QApplication.processEvents()  # Update UI
        
        try:
            # Resolve domain to IP if needed
            if not self.is_valid_ip(ip_or_domain):
                try:
                    ip_or_domain = socket.gethostbyname(ip_or_domain)
                except socket.gaierror:
                    self.status_bar.setText("Invalid IP or domain name")
                    return
            
            # Get IP info from ip-api.com (free tier)
            url = f"http://ip-api.com/json/{ip_or_domain}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            response = requests.get(url)
            data = response.json()
            
            if data.get('status') == 'fail':
                self.status_bar.setText(f"Error: {data.get('message', 'Unknown error')}")
                return
            
            # Display formatted results
            self.display_results(data)
            
            # Show raw JSON
            self.raw_output.setPlainText(json.dumps(data, indent=2))
            self.status_bar.setText("Tracking complete")
            
        except Exception as e:
            self.status_bar.setText(f"Error: {str(e)}")
    
    def is_valid_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def display_results(self, data):
        fields = [
            ("IP Address", data.get('query', 'N/A')),
            ("Continent", f"{data.get('continent', 'N/A')} ({data.get('continentCode', '')})"),
            ("Country", f"{data.get('country', 'N/A')} ({data.get('countryCode', '')})"),
            ("Region", f"{data.get('regionName', 'N/A')} ({data.get('region', '')})"),
            ("City", data.get('city', 'N/A')),
            ("District", data.get('district', 'N/A')),
            ("ZIP Code", data.get('zip', 'N/A')),
            ("Coordinates", f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}"),
            ("Timezone", data.get('timezone', 'N/A')),
            ("ISP", data.get('isp', 'N/A')),
            ("Organization", data.get('org', 'N/A')),
            ("AS Number", data.get('as', 'N/A')),
            ("AS Name", data.get('asname', 'N/A')),
            ("Reverse DNS", data.get('reverse', 'N/A')),
            ("Mobile", "Yes" if data.get('mobile') else "No"),
            ("Proxy/VPN", "Yes" if data.get('proxy') else "No"),
            ("Hosting", "Yes" if data.get('hosting') else "No")
        ]
        
        self.results_table.setRowCount(len(fields))
        
        for row, (field, value) in enumerate(fields):
            self.results_table.setItem(row, 0, QTableWidgetItem(field))
            self.results_table.setItem(row, 1, QTableWidgetItem(str(value)))
            
            # Highlight important fields
            if field in ["Country", "City", "ISP"]:
                for col in range(2):
                    self.results_table.item(row, col).setBackground(Qt.yellow)

if __name__ == "__main__":
    import sys
    import json
    
    app = QApplication(sys.argv)
    tracker = IPTrackerGUI()
    tracker.show()
    sys.exit(app.exec_())
    