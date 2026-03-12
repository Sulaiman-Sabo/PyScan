"""
Synthetic Data Generation for Prototyping
"""
import random
import ast
from typing import List, Dict
import numpy as np

# Templates for vulnerable code patterns
VULNERABLE_TEMPLATES = {
    89: [  # SQL Injection
        """
def func0(var0, var1):
    var2 = "SELECT * FROM users WHERE name = '" + var0 + "'"
    var1.execute(var2)
    return var1.fetchall()
""",
        """
def func0(var0, var1):
    var2 = f"SELECT * FROM accounts WHERE id = {var0}"
    return var1.query(var2)
""",
    ],
    78: [  # Command Injection
        """
def func0(var0):
    import os
    var1 = "ls -la " + var0
    return os.system(var1)
""",
        """
def func0(var0):
    import subprocess
    return subprocess.call(var0, shell=True)
""",
    ],
    798: [  # Hard-coded Credentials
        """
def func0():
    var0 = "admin"
    var1 = "password123"
    return var0, var1
""",
        """
def func0():
    API_KEY = "sk-1234567890abcdef"
    return API_KEY
""",
    ],
    502: [  # Insecure Deserialization
        """
def func0(var0):
    import pickle
    return pickle.loads(var0)
""",
    ],
    22: [  # Directory Traversal
        """
def func0(var0):
    with open("/home/user/data/" + var0, 'r') as var1:
        return var1.read()
""",
    ],
    327: [  # Insecure Cryptography
        """
def func0(var0):
    import hashlib
    return hashlib.md5(var0.encode()).hexdigest()
""",
    ]
}

# Templates for non-vulnerable (safe) code patterns
SAFE_TEMPLATES = [
    """
def func0(var0, var1):
    var2 = [x * 2 for x in var0 if x > var1]
    return sum(var2)
""",
    """
def func0(var0):
    var1 = {}
    for var2 in var0:
        if var2 in var1:
            var1[var2] += 1
        else:
            var1[var2] = 1
    return var1
""",
    """
def func0(var0, var1):
    if var0 > var1:
        return var0
    return var1
""",
]

def generate_synthetic_dataset(n_samples: int = 2000, vulnerable_ratio: float = 0.5) -> List[Dict]:
    """Generate synthetic dataset for prototyping"""
    samples = []
    n_vulnerable = int(n_samples * vulnerable_ratio)
    n_safe = n_samples - n_vulnerable
    
    cwe_ids = list(VULNERABLE_TEMPLATES.keys())
    for i in range(n_vulnerable):
        cwe = random.choice(cwe_ids)
        template = random.choice(VULNERABLE_TEMPLATES[cwe])
        code = template.strip()
        
        samples.append({
            'code': code,
            'label': 1,
            'cwe_id': cwe,
            'is_vulnerable': True,
            'func_name': f'vuln_func_{i}'
        })
    
    for i in range(n_safe):
        template = random.choice(SAFE_TEMPLATES)
        code = template.strip()
        
        samples.append({
            'code': code,
            'label': 0,
            'cwe_id': None,
            'is_vulnerable': False,
            'func_name': f'safe_func_{i}'
        })
    
    random.shuffle(samples)
    return samples

if __name__ == '__main__':
    data = generate_synthetic_dataset(100)
    print(f"Generated {len(data)} samples")
    vuln = sum(1 for d in data if d['is_vulnerable'])
    print(f"Vulnerable: {vuln}, Safe: {len(data) - vuln}")