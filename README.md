# 🛡️ LPMA: Package Manager & Auditor

![Version](https://img.shields.io/badge/version-1.1.1-blue)
![Python](https://img.shields.io/badge/python-3.x-yellow)
![Status](https://img.shields.io/badge/Project-Active-success)

## 📖 Proje Hakkında

**LPMA (Package Manager & Auditor)**, sistemlerdeki yazılım paketlerinin güvenliğini sağlamak amacıyla geliştirilmiş bir otomasyon ve simülasyon aracıdır.

Bu proje, sistemde yüklü olan paketleri (örneğin Python, OpenSSL, Vim) tarayarak yerel bir **CVE (Common Vulnerabilities and Exposures)** veritabanı ile karşılaştırır. Eski ve güvenlik açığı barındıran sürümleri tespit ettiğinde, kullanıcıya durumu raporlar ve tek tuşla **otomatik onarım (Auto-Fix)** imkanı sunar.

Amaç; sistem yöneticilerinin manuel olarak yaptığı güncelleme ve güvenlik yaması süreçlerini otomatize etmek ve kayıt altına almaktır.

## 🚀 Temel Özellikler

* **🔍 Akıllı Zafiyet Taraması:** Sistemdeki paketleri analiz eder, `CRITICAL`, `WARN` veya `SAFE` olarak sınıflandırır.
* **🛡️ Otomatik Onarım (Auto-Fix):** Güvenlik açığı tespit edilen paketleri, en güncel ve güvenli sürümleriyle otomatik olarak değiştirir.
* **📊 Detaylı Loglama:** Yapılan tüm tarama ve güncelleme işlemlerini tarihçesiyle birlikte `install_history.log` dosyasına JSON formatında kaydeder.
* **🐧 Çapraz Platform:** Hem Linux (Bash script ile) hem de Windows (Python ile) ortamlarında çalışabilir.

## 📂 Dosya Yapısı

* `main.py`: Projenin ana kaynak kodu ve simülasyon motoru.
* `run.sh`: Linux sistemler için otomatik kurulum ve başlatma scripti.
* `install_history.log`: Otomatik oluşturulan işlem kayıtları.
* `requirements.txt`: Gerekli Python kütüphaneleri.

## ⚙️ Kurulum ve Çalıştırma

Projeyi çalıştırmak için işletim sisteminize uygun komutu kullanabilirsiniz:

**Linux / macOS için:**
```bash
bash run.sh
