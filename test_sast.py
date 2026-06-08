import unittest
from sast_engine import analyze_code

class TestSastEngine(unittest.TestCase):
    def test_unsafe_eval(self):
        code = "eval(input('Enter code:'))"
        findings, score = analyze_code(code)
        self.assertTrue(any(f['category'] == 'RCE Risk' and 'eval' in f['title'] for f in findings))
        self.assertLess(score, 100)

    def test_command_injection(self):
        code = "import os\nos.system('rm -rf /')"
        findings, score = analyze_code(code)
        self.assertTrue(any(f['category'] == 'Command Injection' for f in findings))
        self.assertLess(score, 100)

    def test_sql_injection(self):
        code = "db.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        findings, score = analyze_code(code)
        self.assertTrue(any(f['category'] == 'SQL Injection' for f in findings))
        self.assertLess(score, 100)

    def test_hardcoded_secrets(self):
        code = "api_key = 'xoxb-1234567890-abcdef'"
        findings, score = analyze_code(code)
        self.assertTrue(any(f['category'] == 'Credential Leak' for f in findings))
        self.assertLess(score, 100)

    def test_syntax_error(self):
        code = "def invalid_syntax("
        findings, score = analyze_code(code)
        self.assertTrue(any(f['category'] == 'Syntax Error' for f in findings))
        self.assertEqual(score, 0)

if __name__ == '__main__':
    unittest.main()
