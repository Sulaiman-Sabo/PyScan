"""
Comprehensive PyScan End-to-End Test Suite
"""

import io
import os
import json
import unittest
import tempfile
from datetime import datetime

TEST_DB_PATH = os.path.abspath("database/test_pyscan.db")
os.environ["DATABASE_PATH"] = TEST_DB_PATH

if os.path.exists(TEST_DB_PATH):
    try:
        os.remove(TEST_DB_PATH)
    except OSError:
        pass

from app import create_app
from database import (
    get_db,
    init_db,
    create_user,
    get_user_by_email,
    get_user_by_username,
    save_scan,
    get_user_scans,
    soft_delete_scan,
    log_action,
    get_system_stats,
)
from auth import validate_password_strength, check_rate_limit, record_failed_attempt, _rate_limit_store
from preprocessor import PythonPreprocessor
from detector import MockDetector, VulnerabilityDetector


class TestPyScanFull(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.app.config["TESTING"] = True

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        _rate_limit_store.clear()

    def tearDown(self):
        self.app_context.pop()

    def test_01_password_validation(self):
        """Test password strength validation logic."""
        valid, msg = validate_password_strength("Weak1!")
        self.assertFalse(valid)
        
        valid, msg = validate_password_strength("ValidPass@2024")
        self.assertTrue(valid)

    def test_02_preprocessor_pipeline(self):
        """Test preprocessor 5-stage pipeline."""
        prep = PythonPreprocessor()
        sample_code = '''
def execute_command(cmd):
    import os
    os.system(cmd)
    return True

def safe_add(a, b):
    return a + b
'''
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(sample_code)
            tmp_path = f.name

        try:
            processed = prep.preprocess_file(tmp_path)
            self.assertEqual(len(processed), 2)
            names = [p["name"] for p in processed]
            self.assertIn("execute_command", names)
            self.assertIn("safe_add", names)
        finally:
            os.remove(tmp_path)

    def test_03_mock_detector(self):
        """Test mock detector predictions on known vulnerable vs safe code."""
        detector = MockDetector()
        
        vuln_func = {
            "name": "vuln_run",
            "code": "def vuln_run(cmd):\n    os.system(cmd)",
            "start_line": 1,
            "raw_tokens": ["def", "vuln_run", "cmd", "os.system", "cmd"],
        }
        res_vuln = detector.predict(vuln_func)
        self.assertTrue(res_vuln["is_vulnerable"])
        self.assertEqual(res_vuln["cwe_category"], "CWE-78: OS Command Injection")
        self.assertEqual(res_vuln["risk_level"], "HIGH")

        safe_func = {
            "name": "safe_calc",
            "code": "def safe_calc(a, b):\n    return a + b",
            "start_line": 10,
            "raw_tokens": ["def", "safe_calc", "a", "b", "return", "a", "b"],
        }
        res_safe = detector.predict(safe_func)
        self.assertFalse(res_safe["is_vulnerable"])
        self.assertEqual(res_safe["cwe_category"], "N/A")
        self.assertEqual(res_safe["risk_level"], "SAFE")

    def test_04_user_registration_and_login(self):
        """Test user registration, login, and session creation."""
        ts = int(datetime.now().timestamp())
        uname = f"user_{ts}"
        email = f"user_{ts}@pyscan.local"

        res_reg = self.client.post(
            "/auth/register",
            data={
                "username": uname,
                "email": email,
                "password": "UserPass@2024",
                "confirm_password": "UserPass@2024",
            },
            follow_redirects=True,
        )
        self.assertEqual(res_reg.status_code, 200)

        res_login = self.client.post(
            "/auth/login",
            data={
                "email": email,
                "password": "UserPass@2024",
            },
            follow_redirects=True,
        )
        self.assertEqual(res_login.status_code, 200)
        self.assertIn(b"WELCOME BACK", res_login.data.upper())

    def test_05_file_scanning_workflow(self):
        """Test file upload scanning, results generation, and report download."""
        res_login = self.client.post(
            "/auth/login",
            data={"email": "admin@pyscan.local", "password": "Admin@PyScan2024"},
            follow_redirects=True,
        )
        self.assertEqual(res_login.status_code, 200)

        test_file_content = b'''
def run_shell(cmd):
    import os
    os.system(cmd)

def get_user_data(user_id):
    import sqlite3
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))

def compute_hash(data):
    import hashlib
    return hashlib.md5(data).hexdigest()

def add_numbers(x, y):
    return x + y
'''
        data = {
            "file": (io.BytesIO(test_file_content), "vulnerable_sample.py")
        }
        res_scan = self.client.post(
            "/scan",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(res_scan.status_code, 200)
        self.assertIn(b"VULNERABILIT", res_scan.data.upper())
        self.assertNotIn(b"vulnerable_sample.py", res_scan.data)

        res_report = self.client.get("/download-report")
        self.assertEqual(res_report.status_code, 200)
        self.assertIn(b"PYSCAN VULNERABILITY DETECTION REPORT", res_report.data.upper())

    def test_06_admin_panel(self):
        """Test admin panel statistics and audit log view."""
        res_login = self.client.post(
            "/auth/login",
            data={"email": "admin@pyscan.local", "password": "Admin@PyScan2024"},
            follow_redirects=True,
        )
        self.assertEqual(res_login.status_code, 200)

        res_admin = self.client.get("/dashboard/admin")
        self.assertEqual(res_admin.status_code, 200)
        self.assertIn(b"ADMIN PANEL", res_admin.data.upper())

    def test_07_privacy_zero_storage_and_folder_scan(self):
        """Test zero-storage privacy compliance and folder/multi-file scanning."""
        res_login = self.client.post(
            "/auth/login",
            data={"email": "admin@pyscan.local", "password": "Admin@PyScan2024"},
            follow_redirects=True,
        )
        self.assertEqual(res_login.status_code, 200)

        file1_content = b'def run_cmd(c):\n    import os\n    os.system(c)\n'
        file2_content = b'def fetch_sql(query):\n    import sqlite3\n    conn = sqlite3.connect("db.sqlite")\n    conn.execute("SELECT * FROM users WHERE " + query)\n'

        data = {
            "file": [
                (io.BytesIO(file1_content), "app/utils.py"),
                (io.BytesIO(file2_content), "app/models.py"),
            ]
        }
        res_folder_scan = self.client.post(
            "/scan",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(res_folder_scan.status_code, 200)
        self.assertIn(b"VULNERABILITY CATEGORY ANALYSIS BREAKDOWN", res_folder_scan.data.upper())

        # Verify database record guarantees zero source code storage
        db = get_db()
        row = db.execute("SELECT scan_result_json FROM scan_history ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIsNotNone(row)
        scan_data = json.loads(row["scan_result_json"])
        
        # Verify CWE distribution summary is stored
        self.assertIn("cwe_summary", scan_data)
        self.assertTrue(len(scan_data["cwe_summary"]) > 0)

        # Verify filename and file paths are fully anonymized
        self.assertTrue(scan_data["filename"].startswith("Anonymized Target"))
        self.assertNotIn("app/utils.py", row["scan_result_json"])
        self.assertNotIn("app/models.py", row["scan_result_json"])
        
        # Verify NO raw source code is stored inside function entries
        for fn in scan_data.get("functions", []):
            self.assertNotIn("code", fn)
            self.assertNotIn("tokens", fn)
            self.assertTrue(fn["filename"].startswith("File "))


if __name__ == "__main__":
    unittest.main()
