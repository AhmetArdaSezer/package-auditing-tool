# 🛡️ LPMA: Linux Package Manager & Auditor
### Enterprise-Grade Vulnerability Scanner & Patch Management Simulation

![Version](https://img.shields.io/badge/version-1.1.1-blue?style=for-the-badge&logo=appveyor)
![Python](https://img.shields.io/badge/python-3.8%2B-yellow?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)

---

## 📖 Proje Özeti ve Amacı

**LPMA (Linux Package Manager & Auditor)**, sistem yöneticileri ve DevOps mühendisleri için geliştirilmiş, sistem güvenliğini proaktif bir şekilde yönetmeyi amaçlayan kapsamlı bir otomasyon aracıdır. Bu proje, **Sistem Programlama** dersi kapsamında, gerçek dünyadaki paket yönetim sistemlerinin (`apt`, `yum`) ve güvenlik tarayıcılarının (`Nessus`, `OpenVAS`) çalışma mantığını simüle etmek amacıyla tasarlanmıştır.

LPMA, sistemdeki kurulu paketleri analiz eder, bilinen güvenlik zafiyetleri (CVE) ile eşleştirir ve kullanıcı onayı ile otomatik iyileştirme (patching) süreçlerini yönetir.

---

## 🚀 Detaylı Özellikler ve Yetenekler

### 1. 🔍 Zafiyet Taraması ve Risk Analizi (Vulnerability Scanning)
LPMA, sistemdeki paketleri tararken sadece sürüm kontrolü yapmaz, aynı zamanda bu sürümleri simüle edilmiş bir **Ulusal Zafiyet Veritabanı (NVD)** ile karşılaştırır.
* **Kritik Seviye Tespiti:** Zafiyetler ciddiyet derecesine göre sınıflandırılır:
    * 🔴 **[CRITICAL]:** Acil müdahale gerektiren yüksek riskli açıklar (Örn: Remote Code Execution).
    * 🟡 **[WARN]:** Orta seviye riskler.
    * 🔵 **[INFO]:** Bilgilendirme amaçlı notlar.
    * 🟢 **[SAFE]:** Güncel ve güvenli paketler.

### 2. 🛡️ Otomatik Onarım Sistemi (Auto-Fix Engine)
Tespit edilen zafiyetler için manuel müdahale gerekmez. "Auto-Fix" modülü devreye girdiğinde:
* Zafiyetli paketin en son kararlı (stable) sürümü belirlenir.
* İndirme, paket açma ve bağımlılık çözme (`dependency resolution`) süreçleri simüle edilir.
* Paket güvenli sürüme yükseltilir ve sistem kararlılığı korunur.

### 3. 📊 Kurumsal Loglama ve Denetim İzi (Audit Logging)
Kurumsal güvenlik standartlarına (ISO 27001) uygun olarak, sistemde yapılan her değişiklik kayıt altına alınır.
* **JSON Formatı:** Loglar, makine tarafından okunabilir (`machine-readable`) JSON formatında tutulur.
* **Veri İçeriği:** İşlem zamanı (`timestamp`), etkilenen paket, eski sürüm, yeni sürüm ve işlem sonucu kaydedilir.
* **Dosya Yolu:** Tüm kayıtlar `install_history.log` dosyasında saklanır.

### 4. ⚡ DevOps ve CI/CD Entegrasyonu
Proje, modern yazılım geliştirme süreçlerine tam uyumludur.
* **GitHub Actions:** `.github/workflows/ci_test.yml` dosyası sayesinde, her kod değişikliğinde (`push`) otomatik testler çalıştırılır.
* **Bash Script Otomasyonu:** `run.sh` scripti, Linux ortamlarında kurulumu ve çalıştırmayı tek komuta indirger.

---

## 📂 Proje Mimarisi ve Dosya Yapısı

Proje, sürdürülebilirlik ve modülerlik ilkelerine göre yapılandırılmıştır:

```text
package-auditing-tool/
├── .github/
│   └── workflows/
│       └── ci_test.yml      # CI/CD Pipeline konfigürasyonu (Otomatik Testler)
├── docs/
│   └── usage.md             # Kullanım kılavuzu ve teknik dokümanlar
├── specs/
│   └── project_info.json    # Proje metadata ve teknik gereksinim dosyası
├── src/
│   └── main.py              # Uygulamanın kaynak kodları (Core Logic)
├── tests/
│   └── test_scanner.py      # Unit test senaryoları
├── .env.example             # Ortam değişkenleri örneği
├── .gitignore               # Git tarafından yok sayılacak dosyalar
├── run.sh                   # Linux başlatma ve kurulum scripti (Bash)
├── requirements.txt         # Python kütüphane bağımlılıkları
├── install_history.log      # Denetim logları (Otomatik oluşturulur)
├── demo_video.mp4           # Projenin çalışmasını gösteren kanıt videosu
└── main.py                  # Ana çalıştırma dosyası (Entry Point)
🛠️ Kurulum ve Kullanım Talimatları
Proje çapraz platform (Cross-Platform) desteğine sahiptir. İşletim sisteminize uygun adımları izleyin.

🐧 Linux / macOS (Otomasyon Modu)
Sistem yöneticileri için hazırlanan Bash scripti ile tüm kurulum ve başlatma işlemleri otomatize edilmiştir.

Bash

# 1. Projeyi klonlayın
git clone [https://github.com/AhmetArdaSezer/package-auditing-tool.git](https://github.com/AhmetArdaSezer/package-auditing-tool.git)

# 2. Dizin içine girin
cd package-auditing-tool

# 3. Çalıştırma izni verin ve başlatın
chmod +x run.sh
./run.sh
Not: run.sh scripti, requirements.txt dosyasındaki kütüphaneleri otomatik kontrol eder ve eksikse kurar.

🪟 Windows (Manuel Mod)
Windows ortamında Python yorumlayıcısı ile doğrudan çalıştırılabilir.

PowerShell

# 1. Gerekli kütüphaneleri yükleyin
pip install -r requirements.txt

# 2. Uygulamayı başlatın
python main.py
🧪 Test Süreçleri
Proje, unittest kütüphanesi kullanılarak yazılmış birim testlerini içerir. Veritabanı bağlantısı ve tarama fonksiyonlarının doğruluğunu test etmek için:

Bash

python -m unittest discover tests
📝 Örnek Log Çıktısı (install_history.log)
Sistem tarafından üretilen denetim kayıtları aşağıdaki standarttadır:

JSON

[
    {
        "timestamp": "2026-01-20 08:45:12",
        "package": "openssl",
        "action": "UPDATE",
        "old_version": "1.1.1f",
        "new_version": "3.0.8",
        "status": "SUCCESS"
    },
    {
        "timestamp": "2026-01-20 08:45:15",
        "package": "python3",
        "action": "UPDATE",
        "old_version": "3.8.10",
        "new_version": "3.11.2",
        "status": "SUCCESS"
    }
