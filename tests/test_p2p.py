import unittest
import sys
import os

# Tambahkan root path agar bisa import node.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestP2PNode(unittest.TestCase):
    def test_node_import(self):
        """Memastikan node.py bisa di-import tanpa error."""
        try:
            import node
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Gagal import node.py: {e}")

if __name__ == '__main__':
    unittest.main()
