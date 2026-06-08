import unittest
import hashlib
from app import app
from database import get_db_connection

class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Seed test data
        self.conn = get_db_connection()
        self.cursor = self.conn.cursor()
        
        # Insert a test user
        self.cursor.execute(
            "INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (999, 'testapi_user', 'hash')"
        )
        # Create a test API key token 'testkey123'
        self.token = 'testkey123'
        self.token_hash = hashlib.sha256(self.token.encode()).hexdigest()
        self.cursor.execute(
            "INSERT OR IGNORE INTO api_keys (user_id, key_value, name) VALUES (999, ?, 'Test CLI')",
            (self.token_hash,)
        )
        self.conn.commit()

    def tearDown(self):
        # Clean up database
        self.cursor.execute("DELETE FROM api_keys WHERE user_id = 999")
        self.cursor.execute("DELETE FROM users WHERE id = 999")
        self.conn.commit()
        self.conn.close()

    def test_unauthorized_missing_header(self):
        response = self.client.get('/api/v1/assets')
        self.assertEqual(response.status_code, 401)
        self.assertIn(b'Missing X-API-KEY header', response.data)

    def test_unauthorized_invalid_key(self):
        headers = {'X-API-KEY': 'wrongkey'}
        response = self.client.get('/api/v1/assets', headers=headers)
        self.assertEqual(response.status_code, 401)
        self.assertIn(b'Invalid API Key', response.data)

    def test_authorized_valid_key(self):
        headers = {'X-API-KEY': self.token}
        response = self.client.get('/api/v1/assets', headers=headers)
        self.assertEqual(response.status_code, 200)
        # Verify JSON list response
        self.assertEqual(response.content_type, 'application/json')

if __name__ == '__main__':
    unittest.main()
