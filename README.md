# 🛡️ Linux Package Manager & Auditor (LPMA)

![Version](https://img.shields.io/badge/version-1.1.1-blue)
![Python](https://img.shields.io/badge/python-3.x-yellow)
![Status](https://img.shields.io/badge/status-stable-green)
![License](https://img.shields.io/badge/license-MIT-orange)

**LPMA**, sistem yöneticileri ve DevOps mühendisleri için geliştirilmiş, Linux paketlerini tarayan, CVE zafiyetlerini analiz eden ve otomatik onarım (patching) sağlayan gelişmiş bir simülasyon aracıdır.

## 🚀 Özellikler

- **🔍 Akıllı Tarama:** Sistemdeki paketleri (`dpkg`/`rpm` simülasyonu) tarar.
- **🛡️ Risk Analizi:** Yerel CVE veritabanı ile sürümleri karşılaştırır (`CRITICAL`, `WARN`, `SAFE`).
- **🛠️ Auto-Fix (Otomatik Onarım):** Zafiyetli paketleri tespit eder, güncel sürümü indirir ve kurar.
- **📊 Loglama:** Tüm güncelleme işlemlerini `install_history.log` dosyasına JSON formatında kaydeder.
- **🎨 Görsel Arayüz:** Renkli terminal çıktıları ile kolay okunabilirlik sağlar.

## 📂 Proje Yapısı

```bash
package-auditing-tool/
├── .github/workflows/    # CI/CD Pipeline (GitHub Actions)
├── docs/                 # Kullanım dokümantasyonu
├── specs/                # Proje teknik özellikleri (JSON)
├── src/                  # Kaynak kodlar (Opsiyonel)
├── tests/                # Unit test senaryoları
├── main.py               # Ana uygulama dosyası
├── run.sh                # Linux başlatma scripti
├── requirements.txt      # Kütüphane bağımlılıkları
└── install_history.log   # Kurulum kayıtları
