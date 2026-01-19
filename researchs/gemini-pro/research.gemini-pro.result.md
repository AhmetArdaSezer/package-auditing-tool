# Linux Paket Denetim ve Zafiyet Tarama Aracı (Python Tabanlı) Araştırma Raporu

Bu rapor, Linux işletim sistemlerinde kurulu paketlerin güvenlik açıklarını (CVE) tespit etmek için Python tabanlı bir denetim aracı geliştirilmesi veya kullanılması üzerine odaklanmaktadır.

## 1. Temel Çalışma Prensipleri

Python tabanlı bir Linux paket denetim aracının mimarisi üç ana aşamadan oluşur: **Veri Toplama (Collection)**, **Normalizasyon (Normalization)** ve **Karşılaştırma (Matching)**.

* **Envanter Çıkarma (Inventory Extraction):**
    * Python'un `subprocess` modülü veya `python-apt` (Debian/Ubuntu) ve `rpm-python` (Red Hat/CentOS) kütüphaneleri kullanılarak sistemde kurulu paketlerin listesi çekilir.
    * *Örnek:* `dpkg-query -W -f='${binary:Package} ${Version}\n'` komutunun çıktısını parse etmek.
* **Zafiyet Veritabanı Entegrasyonu:**
    * Araç, NVD (National Vulnerability Database), OVAL (Open Vulnerability and Assessment Language) veya dağıtıma özel (Ubuntu CVE Tracker, Alpine SecDB) kaynaklardan güncel zafiyet verilerini çeker.
* **Sürüm Karşılaştırma Mantığı (Versioning Logic):**
    * En kritik aşamadır. Kurulu paketin sürümü (örn: `2.4.5-1ubuntu2`), zafiyet veritabanındaki "etkilenen sürümler" (örn: `< 2.4.6`) ile karşılaştırılır.
    * Python'daki `packaging.version` veya dağıtıma özel sürüm karşılaştırma algoritmaları (örn: `apt_pkg.version_compare`) kullanılır.

## 2. En İyi Uygulama Yöntemleri (Best Practices) ve Standartlar

* **SBOM (Software Bill of Materials) Kullanımı:** Modern tarayıcılar, tarama sonucunda CycloneDX veya SPDX formatında bir SBOM üretmelidir. Bu, endüstri standardı bir raporlama formatıdır.
* **Distro-Aware Scanning (Dağıtım Farkındalığı):** Bir paket "upstream" (kaynak kod) sürümünde zafiyet barındırabilir ancak Linux dağıtımı (Debian/RHEL) bu zafiyeti "backport" (yama) yöntemiyle çözmüş olabilir. Aracın sadece sürüm numarasına bakmak yerine dağıtımın güvenlik bildirimlerini (DSA/USN) dikkate alması gerekir.
* **Ayrıcalık Yönetimi (Least Privilege):** Tarama aracı sadece paket veritabanını okumalı (`/var/lib/dpkg/status` vb.), root yetkisi gerektiren yazma işlemlerinden kaçınmalıdır.
* **CI/CD Entegrasyonu:** Aracın, geliştirme sürecinde otomatik çalışabilmesi için CLI desteği sunması ve çıkış kodlarını (exit codes) standartlara (başarılı: 0, zafiyet bulundu: 1) uygun vermesi gerekir.

## 3. Benzer Açık Kaynak Projeler ve Rakipler

Python tabanlı geliştirilecek bir aracın piyasadaki başlıca rakipleri ve benzerleri şunlardır:

| Araç | Dil | Odak Alanı | Özellikler |
| :--- | :--- | :--- | :--- |
| **Vuls (Vulnerability Scanner)** | Go | Sistem/Ağ | Ajanlı/Ajansız tarama, çok detaylı raporlama. En güçlü rakiplerden biridir. |
| **Lynis** | Shell | Sistem Hardening | Zafiyetten ziyade yapılandırma hatalarını ve hardening eksiklerini denetler. |
| **Trivy** | Go | Konteyner/FS | Dosya sistemi ve konteyner imajlarındaki paketleri çok hızlı tarar. |
| **OpenVAS** | C/Python | Ağ/Zafiyet | Geniş kapsamlı ağ zafiyet tarayıcısıdır, sadece paket denetimi ile sınırlı değildir. |
| **pip-audit** | Python | Python Paketleri | Sadece Python ortamındaki (pip) paketleri denetler, OS paketlerine odaklanmaz. |

## 4. Kritik Yapılandırma Dosyaları ve Parametreleri

Aracın doğru çalışması için etkileşime girdiği veya yapılandırdığı kritik dosyalar:

* **Sistem Tanımlama Dosyaları:**
    * `/etc/os-release`: İşletim sistemi dağıtımını ve sürümünü (Debian 11, Ubuntu 22.04 vb.) tespit etmek için okunur.
* **Paket Veritabanları (Read-Only):**
    * `/var/lib/dpkg/status`: Debian tabanlı sistemlerde kurulu paketlerin veritabanı.
    * `/var/lib/rpm/Packages`: RPM tabanlı sistemlerdeki veritabanı.
* **Yapılandırma Parametreleri (tool.conf):**
    * `MIN_SEVERITY`: Raporlanacak minimum CVE seviyesi (Low, Medium, High, Critical).
    * `IGNORE_CVES`: "False positive" veya kabul edilmiş risk olarak işaretlenen CVE listesi.
    * `DB_UPDATE_INTERVAL`: Zafiyet veritabanının ne sıklıkla güncelleneceği.

## 5. Güvenlik Açısından Kritik Noktalar

* **False Positive/Negative Yönetimi:** Yanlış sürüm ayrıştırması (parsing), sistemin güvensiz olduğu halde güvenli sanılmasına (False Negative) yol açabilir. Sürüm karşılaştırma regex'leri çok titiz hazırlanmalıdır.
* **Veritabanı Bütünlüğü:** Zafiyet veritabanları (NVD feed'leri) indirilirken HTTPS ve imza kontrolü yapılmalıdır. "Man-in-the-middle" saldırısı ile veritabanı manipüle edilirse araç kör edilebilir.
* **DoS (Denial of Service) Riski:** "Zip bomb" benzeri, çok derin bağımlılık ağaçları veya bozuk paket meta verileri tarayıcıyı kilitlememelidir.
* **Input Sanitization:** Eğer araç uzaktan bir makineyi tarıyorsa, SSH üzerinden gelen veriler (hostname, paket isimleri) temizlenmeden `exec()` fonksiyonlarına sokulmamalıdır.

---

### Ek: Infographic (Sistem Mimarisi)

Aşağıdaki diyagram, Python tabanlı bir paket denetim aracının akış şemasını özetlemektedir:

```mermaid
graph TD
    A[Başlat: Python Scanner] --> B{OS Tespiti}
    B -- Debian/Ubuntu --> C[dpkg/apt Verisini Oku]
    B -- RHEL/CentOS --> D[rpm/yum Verisini Oku]
    C --> E[Paket Listesi JSON]
    D --> E
    E --> F[CVE Veritabanı ile Karşılaştır]
    F --> G{Zafiyet Var mı?}
    G -- Evet --> H[Kritiklik Seviyesini Belirle]
    G -- Hayır --> I[Sonraki Paket]
    H --> J[Rapor Oluştur (HTML/JSON)]
    I --> F
