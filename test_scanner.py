import unittest
import socket
from scanner import is_ssrf_safe

class TestSSRFProtection(unittest.TestCase):
    def test_localhost_blocked(self):
        self.assertFalse(is_ssrf_safe("http://127.0.0.1"))
        self.assertFalse(is_ssrf_safe("http://localhost"))
        self.assertFalse(is_ssrf_safe("https://localhost:5000"))
        
    def test_private_ips_blocked(self):
        self.assertFalse(is_ssrf_safe("http://192.168.1.1"))
        self.assertFalse(is_ssrf_safe("http://10.0.0.1"))
        self.assertFalse(is_ssrf_safe("https://172.16.0.1"))
        self.assertFalse(is_ssrf_safe("http://169.254.169.254")) # AWS Metadata
        
    def test_public_ips_allowed(self):
        # Resolve a public hostname to be sure it's public
        try:
            ip = socket.gethostbyname("example.com")
            # example.com should be safe unless they run it on an internal DNS redirect, 
            # but standard example.com resolves to 93.184.215.14
            self.assertTrue(is_ssrf_safe("http://example.com"))
        except socket.gaierror:
            # Skip if offline
            pass

if __name__ == '__main__':
    unittest.main()
