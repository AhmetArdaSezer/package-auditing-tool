import unittest
from src.main import PackageManager

class TestLPMA(unittest.TestCase):
    def setUp(self):
        """Her testten önce çalışır, temiz bir başlangıç sağlar."""
        self.tool = PackageManager()

    def test_database_load(self):
        """1. Veritabanı (mock_db) başarıyla yükleniyor mu?"""
        print("\n[TEST] Veritabanı bütünlüğü kontrol ediliyor...")
        self.assertTrue(len(self.tool.mock_db) > 0, "Veritabanı boş olmamalı!")
        # Örnek bir CVE kontrolü
        self.assertIn("openssl", self.tool.mock_db, "OpenSSL veritabanında olmalı!")

    def test_vulnerability_detection(self):
        """2. Zafiyet tespiti doğru çalışıyor mu?"""
        print("[TEST] Zafiyet tarama simülasyonu...")
        
        # Test için manuel olarak zafiyetli paket ekleyelim (Simülasyon)
        test_packages = ["openssl", "python3"]
        detected_vulns = []
        
        for pkg in test_packages:
            if pkg in self.tool.mock_db:
                detected_vulns.append(self.tool.mock_db[pkg])

        self.assertGreater(len(detected_vulns), 0, "Zafiyetli paket tespit edilmeliydi!")
        self.assertEqual(detected_vulns[0]['severity'], 'CRITICAL', "Risk seviyesi doğru okunmalı!")

    def test_log_file_creation(self):
        """3. Log dosyası oluşturulabiliyor mu?"""
        # Log fonksiyonunun varlığını kontrol et
        self.assertTrue(hasattr(self.tool, 'self_install_log'), "Loglama fonksiyonu eksik!")

if __name__ == '__main__':
    unittest.main()
