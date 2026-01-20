import time
import random
import json
from datetime import datetime

# Renklendirme kütüphanesi (Hata vermesin diye try-except bloğu)
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # EĞER KÜTÜPHANE YOKSA BU KISIM ÇALIŞIR
    # Düzeltme: Buraya MAGENTA ve diğer tüm renkleri ekledim.
    class Fore: 
        GREEN = RED = YELLOW = CYAN = WHITE = BLUE = MAGENTA = ""
    class Style: 
        RESET_ALL = BRIGHT = ""

class PackageManager:
    def __init__(self):
        # Simülasyon Veritabanımız (Hem Zafiyetli Hem Güncel Sürümler)
        self.mock_db = {
            "openssl": {"current": "1.1.1f", "fixed": "3.0.8", "cve": "CVE-2023-0286", "severity": "HIGH"},
            "python3": {"current": "3.8.10", "fixed": "3.11.2", "cve": "CVE-2021-3177", "severity": "MEDIUM"},
            "curl": {"current": "7.68.0", "fixed": "7.68.0", "cve": "None", "severity": "SAFE"},
            "vim": {"current": "8.1.2269", "fixed": "9.0.0", "cve": "CVE-2022-2255", "severity": "LOW"},
            "bash": {"current": "5.0.17", "fixed": "5.0.17", "cve": "None", "severity": "SAFE"},
            "git": {"current": "2.25.1", "fixed": "2.25.1", "cve": "None", "severity": "SAFE"}
        }
        self.install_logs = []

    def print_banner(self):
        print(Fore.CYAN + Style.BRIGHT + """
        ===================================================
           LINUX PACKAGE MANAGER & AUDITOR (LPMA) v1.1.1
           Ops: Scan | Audit | Auto-Fix | Update | Log
           Developed by: Ahmet Arda Sezer
        ===================================================
        """ + Style.RESET_ALL)

    def loading_animation(self, text, duration=1.5):
        print(Fore.YELLOW + f"[*] {text}...", end='\r')
        time.sleep(duration)
        print(f"{' ' * 60}", end='\r') # Satırı temizle

    def scan_and_audit(self):
        print(Fore.YELLOW + "\n[*] MOD: Zafiyet Taraması Başlatılıyor...")
        self.loading_animation("Paket veritabanı (dpkg) okunuyor")
        self.loading_animation("NVD veritabanı (Local DB) ile eşleştiriliyor")
        
        print(f"\n{'PAKET':<15} {'MEVCUT':<10} {'DURUM':<10} {'CVE KODU'}")
        print("-" * 55)

        vulnerable_packages = []
        
        for pkg, info in self.mock_db.items():
            time.sleep(0.2)
            if info["severity"] == "HIGH":
                color = Fore.RED + Style.BRIGHT
                status = "[CRITICAL]"
                vulnerable_packages.append(pkg)
            elif info["severity"] == "MEDIUM":
                color = Fore.YELLOW
                status = "[WARN]"
                vulnerable_packages.append(pkg)
            elif info["severity"] == "LOW":
                color = Fore.BLUE
                status = "[INFO]"
                vulnerable_packages.append(pkg)
            else:
                color = Fore.GREEN
                status = "[SAFE]"
            
            print(f"{color}{pkg:<15} {info['current']:<10} {status:<10} {info['cve']}{Style.RESET_ALL}")

        return vulnerable_packages

    def auto_fix(self, vuln_list):
        if not vuln_list:
            print(Fore.GREEN + "\n[+] Sistem güvenli, düzeltilecek paket yok.")
            return

        print(Fore.MAGENTA + Style.BRIGHT + f"\n[!] {len(vuln_list)} Riskli paket tespit edildi. Otomatik onarım başlatılıyor...\n")
        time.sleep(1)

        for pkg in vuln_list:
            target_ver = self.mock_db[pkg]["fixed"]
            print(Fore.YELLOW + f"[*] {pkg} indiriliyor ve kuruluyor (v{target_ver})...")
            
            # İndirme Simülasyonu
            time.sleep(0.8)
            print(Fore.CYAN + f"    -> {pkg}.deb bağımlılıkları çözülüyor...")
            time.sleep(0.6)
            print(Fore.GREEN + f"    -> [OK] {pkg} başarıyla güncellendi.\n")
            
            # Log Kaydı
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "package": pkg,
                "action": "UPDATE",
                "old_version": self.mock_db[pkg]["current"],
                "new_version": target_ver,
                "status": "SUCCESS"
            }
            self.install_logs.append(log_entry)
        
        # Logları Dosyaya Yaz
        with open("install_history.log", "w") as log_file:
            json.dump(self.install_logs, log_file, indent=4)

        print(Fore.GREEN + Style.BRIGHT + "[✔] TÜM SİSTEM GÜVENLİ HALE GETİRİLDİ.")
        print(Fore.WHITE + "Log kaydı oluşturuldu: install_history.log")

if __name__ == "__main__":
    tool = PackageManager()
    tool.print_banner()
    
    # 1. Aşama: Tara
    risks = tool.scan_and_audit()
    
    # 2. Aşama: Kullanıcıya Sor (Yönetim Kısmı)
    if risks:
        print(Fore.WHITE + "\nNe yapmak istersiniz?")
        print("1. Sadece Raporla ve Çık")
        print("2. Otomatik Güncelle ve Onar (Auto-Fix)")
        
        choice = input(Fore.YELLOW + "\nSeçiminiz (1/2): " + Style.RESET_ALL)
        
        if choice == '2':
            tool.auto_fix(risks)
        else:
            print(Fore.CYAN + "\n[INFO] Rapor kaydedildi. Çıkış yapılıyor.")
