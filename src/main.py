import time
import random

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'

def scan_system():
    print(Colors.GREEN + "[*] Linux Package Auditing Tool v1.0 başlatılıyor..." + Colors.RESET)
    time.sleep(1)
    print("CVE Veritabanı simülasyonu yükleniyor...")
    time.sleep(1)
    
    # Simüle edilmiş zafiyet taraması
    packages = ["openssl", "python3", "kernel", "log4j"]
    for pkg in packages:
        print(f"[*] Taranıyor: {pkg}...")
        time.sleep(0.5)
        
    print(Colors.RED + "\n[!] KRİTİK ZAFİYET TESPİT EDİLDİ: log4j v2.14 (CVE-2021-44228)" + Colors.RESET)
    print("Rapor oluşturuldu: security_report.txt")

if __name__ == "__main__":
    scan_system()
