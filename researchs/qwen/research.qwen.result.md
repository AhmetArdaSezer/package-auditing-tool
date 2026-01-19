
# Linux İşletim Sistemleri İçin Python Tabanlı Zafiyet Tarama ve Paket Denetim Aracı (Linux Package Auditing Tool)  
**Teknik Araştırma Raporu**  
*Güncelleme Tarihi: 19 Ocak 2026*  

---

## 1. Temel Çalışma Prensipleri

### 1.1. Paket Bilgisi Toplama
Python tabanlı bir zafiyet tarama aracı, işletim sistemindeki kurulmuş paketleri **sistem paket yöneticisi API'leri** üzerinden toplar:
- **Debian/Ubuntu**: `dpkg -l` veya `apt` komutlarının çıktısı (örn. `python-apt` kütüphanesi)
- **RHEL/CentOS**: `rpm -qa` veya `dnf` komutları (örn. `rpm` Python modülü)
- **Genel**: `pkg` (BSD), `pacman` (Arch) gibi araçlar için özel parser'lar

**Örnek Kod Parçası** (cve-bin-tool referansı):  
```python
from cve_bin_tool import scanner
scanner = scanner.Scanner()
installed_packages = scanner.get_installed_packages()
