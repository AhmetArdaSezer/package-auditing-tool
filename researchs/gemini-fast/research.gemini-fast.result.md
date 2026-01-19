# Linux Paket Denetim ve Zafiyet Tarama Aracı Araştırma Raporu

## 1. Temel Çalışma Prensipleri
Python tabanlı bir tarayıcı şu üç aşamalı döngü ile çalışır:
* **Envanter Toplama:** `subprocess` modülü üzerinden `dpkg`, `rpm` veya `pip list` gibi komutlarla kurulu paketlerin ve versiyonların listelenmesi.
* **Veri Eşleştirme:** Toplanan versiyon bilgilerinin CVE (Common Vulnerabilities and Exposures) veritabanları ile karşılaştırılması.
* **Puanlama:** Tespit edilen açıkların CVSS skorlarına göre (0-10 arası) derecelendirilmesi.

## 2. En İyi Uygulamalar (Best Practices)
* **SBOM Entegrasyonu:** Aracın sadece paketleri değil, bağımlılık ağacını (dependency tree) analiz etmesi sağlanmalıdır.
* **VEX (Vulnerability Exploitability eXchange):** Zafiyetin sistemde gerçekten sömürülebilir olup olmadığını belirten ek protokollerin kullanılması.
* **Düzenli Veritabanı Güncelleme:** Yerel veri havuzunun günlük olarak NVD veya GitHub Advisory gibi kaynaklarla senkronize edilmesi.

## 3. Benzer Projeler ve Rakipler
* **Trivy:** Konteyner ve işletim sistemi paketleri için sektör standardı.
* **Grype:** SBOM taraması için optimize edilmiş, hızlı bir zafiyet motoru.
* **Lynis:** Güvenlik denetimi ve sistem sıkılaştırma (hardening) aracı.

## 4. Kritik Yapılandırma ve Güvenlik
* **Yapılandırma:** `config.yaml` dosyasında zafiyet eşik değerleri (severity_threshold) ve istisna listeleri (exclude_list) tanımlanmalıdır.
* **Güvenlik Riski:** Tarayıcı `root` yetkisiyle çalıştığı için, kodun dışarıdan komut enjeksiyonuna (command injection) karşı izole edilmesi kritiktir.
