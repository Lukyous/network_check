import sys
import subprocess
import socket
import struct
import time
import threading
from scapy.all import ARP, Ether, srp
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtCore import Qt, QTimer, QSize
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QLabel

target_ip = "192.168.1.1/24"

devices_info = {}

def nom_check(ip):
    namesear = subprocess.run(f"nslookup {ip}", text=True, capture_output=True).stdout
    namesear = str(namesear)
    if "Nom" or "Name" in namesear:
        namesear = namesear.split()
        name = namesear[-3]
        if ".home" in name:
            name = name.strip(".home")
    else:
        name = "nom introuvable"
    return name

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def check_ip_name_mac():
    global devices_info
    arp_request = ARP(pdst=target_ip)
    ether_request = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request
    answered_list = srp(ether_request, timeout=2, verbose=False)[0]
    answered_list.sort(key=lambda x: ip_to_int(x[1].psrc))

    current_time = time.time()

    for sent, received in answered_list:
        ip = received.psrc
        mac = received.hwsrc
        name = nom_check(ip)

        if ip not in devices_info:
            devices_info[ip] = {
                'mac': mac,
                'name': name,
                'last_seen': current_time
            }
        else:
            devices_info[ip]['last_seen'] = current_time

    devices_to_remove = [ip for ip, info in devices_info.items() if current_time - info['last_seen'] > 60]  
    for ip in devices_to_remove:
        del devices_info[ip]

    sorted_devices = sorted(devices_info.items(), key=lambda x: ip_to_int(x[0]))

    return sorted_devices

class NetworkMonitorThread(threading.Thread):
    def __init__(self, update_callback):
        super().__init__()
        self.update_callback = update_callback
        self.is_running = True

    def run(self):
        while self.is_running:
            sorted_devices = check_ip_name_mac()
            self.update_callback(sorted_devices)
            time.sleep(1) 

    def stop(self):
        self.is_running = False

class AppWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Device Monitor")
        self.setGeometry(100, 100, 600, 400)

        self.is_running = False 
        self.monitor_thread = None 

        button_layout = QHBoxLayout()

        self.play_button = QPushButton()
        self.play_button.setFixedSize(23, 23)  
        self.play_button.setIconSize(QSize(17, 17)) 
        self.play_button.clicked.connect(self.toggle_check_loop)

        self.play_icon = QIcon("icon/play_icon.png") 
        self.stop_icon = QIcon("icon/stop_icon.png") 

        self.play_button.setIcon(self.play_icon)
        button_layout.addWidget(self.play_button, alignment=Qt.AlignLeft)

        self.status_label = QLabel("Scan arrêté")
        self.status_label.setAlignment(Qt.AlignLeft) 

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "Nom"])

        layout = QVBoxLayout()
        layout.addLayout(button_layout)  
        layout.addWidget(self.status_label)  
        layout.addWidget(self.table)

        self.setLayout(layout)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_table)
        self.timer.start(2000)

    def toggle_check_loop(self):
        if self.is_running:
            self.is_running = False
            self.play_button.setIcon(self.play_icon)  
            self.status_label.setText("Scan arrêté")  

            if self.monitor_thread:
                self.monitor_thread.stop()

            self.monitor_thread = None

        else:
            self.is_running = True
            self.play_button.setIcon(self.stop_icon) 
            self.status_label.setText("Scan en cours...") 
            self.monitor_thread = NetworkMonitorThread(self.update_table)
            self.monitor_thread.start()

    def update_table(self, sorted_devices=None):
        if sorted_devices is None:
            return

        self.table.setRowCount(len(sorted_devices))
        for row, (ip, info) in enumerate(sorted_devices):
            self.table.setItem(row, 0, QTableWidgetItem(ip))
            self.table.setItem(row, 1, QTableWidgetItem(info['mac']))
            self.table.setItem(row, 2, QTableWidgetItem(info['name']))

    def closeEvent(self, event):
        if self.monitor_thread:
            self.monitor_thread.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AppWindow()
    window.show()
    sys.exit(app.exec())