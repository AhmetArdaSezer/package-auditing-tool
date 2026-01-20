import unittest
from src.main import PackageManager

class TestLPMA(unittest.TestCase):
    def setUp(self):
        self.tool = PackageManager()

    def test_database_load(self):
        self.assertTrue(len(self.tool.mock_db) > 0)

if __name__ == '__main__':
    unittest.main()
