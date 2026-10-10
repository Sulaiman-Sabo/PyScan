import requests
import re
import os

with open("test_upload.py", "w") as f:
    f.write("""def test_func():\n    import os\n    os.system("echo injected")\n    print("hello")\n""")

s = requests.Session()
r = s.get("http://127.0.0.1:5000/auth/login")
csrf_token = re.search(r'name="csrf_token".*?value="([^"]+)"', r.text).group(1)

login_data = {
    "csrf_token": csrf_token,
    "email": "admin@pyscan.local",
    "password": "Admin@PyScan2024"
}
s.post("http://127.0.0.1:5000/auth/login", data=login_data)

with open("test_upload.py", "rb") as f:
    r2 = s.get("http://127.0.0.1:5000/scan")
    csrf_match = re.search(r'name="csrf_token".*?value="([^"]+)"', r2.text)
    scan_data = {"csrf_token": csrf_match.group(1)} if csrf_match else {}
    
    r3 = s.post("http://127.0.0.1:5000/scan", files={"file": ("test_upload.py", f, "text/x-python")}, data=scan_data)

r4 = s.get("http://127.0.0.1:5000/results")
print(r4.text)

