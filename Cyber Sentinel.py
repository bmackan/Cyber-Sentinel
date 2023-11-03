import socket
import sys
import time
import threading
import colorama

from pprint import pprint

# İmza tabanlı tespit için saldırı imzaları
signatures = {
    "SYN flood": b"SYN",
    "UDP flood": b"UDP",
    "ICMP flood": b"ICMP",
}

# Davranışsal tespit için anormallikler
anomalies = {
    "Anormal ağ trafiği": lambda data: len(data) > 100000,
    "Anormal sistem günlükleri": lambda data: "failed login" in data,
    "Anormal kullanıcı etkinlikleri": lambda data: "malware" in data,
}

# Monitör ekranını temizler
def clear_screen():
    os.system("clear")

# Uyarı mesajını gösterir
def show_alert(message):
    colorama.init()
    print(colorama.Fore.RED + "Saldırı tespit edildi!" + colorama.Style.RESET_ALL)
    print(message)

# Ağ trafiğini dinler
def listen_for_traffic():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
        sock.bind(("0.0.0.0", 0))
        sock.settimeout(10)  # 10 saniyelik zaman aşımı

        while True:
            try:
                # Yeni veri alın
                data, addr = sock.recvfrom(65535)
            except BlockingIOError:
                # sock.recvfrom() geçici olarak kullanılamıyor
                continue

            # Verileri analiz edin
            for signature in signatures:
                if signature in data:
                    message = "Saldırı tespit edildi: {} (imza tabanlı)".format(signature)
                    show_alert(message)
                    break

            for anomaly in anomalies:
                if anomaly(data):
                    message = "Saldırı tespit edildi: {} (davranışsal)".format(anomaly.__name__)
                    show_alert(message)
                    break

            # Verileri monitörde gösterin
            clear_screen()
            pprint(data)

            # Eksik paketleri kontrol edin
            missing_packages = check_for_missing_packages()

            # Eksik paketleri yükleyin
            if missing_packages:
                install_missing_packages(missing_packages)

# Monitör ekranını günceller
def update_monitor():
    while True:
        time.sleep(1)
        clear_screen()
        pprint(data)

# Ana programı başlatır
def main():
    # Ağ trafiğini dinleyin
    thread1 = threading.Thread(target=listen_for_traffic)
    thread1.start()

    # Monitör ekranını güncelleyin
    thread2 = threading.Thread(target=update_monitor)
    thread2.start()

if __name__ == "__main__":
    main()