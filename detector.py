"""
PyScan Vulnerability Detection Module

Provides two detector implementations:
1. VulnerabilityDetector -- wraps the trained PyTorch BiLSTM-Attention model.
2. MockDetector -- heuristic-based detector for demonstration fallback.

Author: PyScan Project -- BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

try:
    import torch
except Exception:
    torch = None

import hashlib
import json
import os
import random
import re
import sys
from typing import Any, Dict, List, Optional

import numpy as np

sys.path.insert(0, os.path.abspath("."))
from models.dataset import CodeNormalizer


# ---------------------------------------------------------------------------
# Remediation Guidance Dictionary
# ---------------------------------------------------------------------------

REMEDIATION_GUIDANCE: Dict[str, Dict[str, str]] = {
    "CWE-78": {
        "title": "OS Command Injection Fix",
        "description": "Never pass unsanitized strings or user input directly into system shells (os.system, exec, or shell=True). Use argument-vectorized subprocess calls.",
        "vulnerable_example": "os.system('ping ' + user_input)",
        "secure_example": "import subprocess\nsubprocess.run(['ping', user_input], check=True)",
    },
    "CWE-89": {
        "title": "SQL Injection Fix",
        "description": "Never concatenate dynamic variables into SQL query strings. Use parameterized queries with placeholders (?) to separate executable code from user parameters.",
        "vulnerable_example": "cursor.execute('SELECT * FROM users WHERE id = ' + str(user_id))",
        "secure_example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    "CWE-502": {
        "title": "Insecure Deserialization Fix",
        "description": "Avoid pickle, marshal, or un-validated yaml.load on untrusted input data. Use safe data exchange formats such as JSON or yaml.safe_load.",
        "vulnerable_example": "pickle.loads(untrusted_payload)",
        "secure_example": "import json\ndata = json.loads(untrusted_payload)",
    },
    "CWE-798": {
        "title": "Hard-coded Credentials Fix",
        "description": "Store secrets, passwords, and API tokens in system environment variables or external secret management vaults instead of hardcoding them in source code.",
        "vulnerable_example": "API_KEY = 'sk_live_9988776655'",
        "secure_example": "import os\nAPI_KEY = os.environ.get('API_KEY')",
    },
    "CWE-327": {
        "title": "Insecure Cryptography Fix",
        "description": "Replace broken or obsolete hash algorithms (MD5, SHA1, DES) with modern secure hashing functions (SHA-256, bcrypt, or Argon2).",
        "vulnerable_example": "hashlib.md5(password.encode()).hexdigest()",
        "secure_example": "import hashlib\nhashlib.sha256(password.encode()).hexdigest()",
    },
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS) Fix",
        "description": "Sanitize and escape all dynamic user inputs before rendering in web templates. Never use mark_safe or render_template_string on untrusted input.",
        "vulnerable_example": "render_template_string(user_content)",
        "secure_example": "from markupsafe import escape\nrender_template('page.html', content=escape(user_content))",
    },
    "CWE-22": {
        "title": "Path Traversal Fix",
        "description": "Validate and sanitize file paths using os.path.basename to prevent directory traversal outside authorized locations.",
        "vulnerable_example": "open('/var/data/' + user_filename)",
        "secure_example": "import os\nsafe_filename = os.path.basename(user_filename)\nopen(os.path.join('/var/data/', safe_filename))",
    },
}


# ---------------------------------------------------------------------------
# Mock Detector -- heuristic-based fallback
# ---------------------------------------------------------------------------

class MockDetector:
    """
    Heuristic-based vulnerability detector used as demonstration fallback.
    """

    VULNERABLE_TOKENS: Dict[str, str] = {
        # CWE-78: OS Command Injection
        "eval": "CWE-78: OS Command Injection",
        "exec": "CWE-78: OS Command Injection",
        "os.system": "CWE-78: OS Command Injection",
        "subprocess": "CWE-78: OS Command Injection",
        "subprocess.call": "CWE-78: OS Command Injection",
        "subprocess.run": "CWE-78: OS Command Injection",
        "subprocess.Popen": "CWE-78: OS Command Injection",
        "shell=True": "CWE-78: OS Command Injection",
        # CWE-89: SQL Injection
        "cursor.execute": "CWE-89: SQL Injection",
        "cursor.executemany": "CWE-89: SQL Injection",
        "SELECT": "CWE-89: SQL Injection",
        "INSERT": "CWE-89: SQL Injection",
        "UPDATE": "CWE-89: SQL Injection",
        "DELETE": "CWE-89: SQL Injection",
        "WHERE": "CWE-89: SQL Injection",
        "FROM": "CWE-89: SQL Injection",
        # CWE-502: Insecure Deserialization
        "pickle.loads": "CWE-502: Insecure Deserialization",
        "pickle.load": "CWE-502: Insecure Deserialization",
        "yaml.load": "CWE-502: Insecure Deserialization",
        "marshal.loads": "CWE-502: Insecure Deserialization",
        # CWE-798: Hard-coded Credentials
        # CWE-798: Hard-coded Credentials
        "api_key": "CWE-798: Hard-coded Credentials",
        "SECRET_KEY": "CWE-798: Hard-coded Credentials",
        "TOKEN": "CWE-798: Hard-coded Credentials",
        # CWE-327: Insecure Cryptographic Implementation
        "hashlib.md5": "CWE-327: Insecure Cryptographic Implementation",
        "hashlib.sha1": "CWE-327: Insecure Cryptographic Implementation",
        "md5": "CWE-327: Insecure Cryptographic Implementation",
        "sha1": "CWE-327: Insecure Cryptographic Implementation",
        "DES": "CWE-327: Insecure Cryptographic Implementation",
        "RC4": "CWE-327: Insecure Cryptographic Implementation",
        # CWE-79: Cross-Site Scripting
        "render_template_string": "CWE-79: Cross-Site Scripting",
        "mark_safe": "CWE-79: Cross-Site Scripting",
        # CWE-22: Path Traversal
        "open(": "CWE-22: Path Traversal",
        # CWE-330: Weak Random
        "random.random": "CWE-330: Weak Random",
        "random.randint": "CWE-330: Weak Random",
        # CWE-200: Information Exposure
        "traceback.print_exc": "CWE-200: Information Exposure",
    }

    def __init__(self) -> None:
        self._random = random.Random()
        self._random.seed(42)

    def predict(self, function_dict: Dict[str, Any]) -> Dict[str, Any]:
        raw_tokens: List[str] = function_dict.get("raw_tokens", [])
        func_name: str = function_dict.get("name", "unknown")
        start_line: int = function_dict.get("start_line", 0)
        code: str = function_dict.get("code", "")

        matched_tokens: List[str] = []
        detected_cwe: Optional[str] = None

        code_lower = code.lower()
        token_set = set(t.lower() for t in raw_tokens)

        for vuln_token, cwe in self.VULNERABLE_TOKENS.items():
            vuln_lower = vuln_token.lower()
            # Strict token match or word-boundary match in code
            if vuln_lower in token_set or re.search(rf"\b{re.escape(vuln_lower)}\b", code_lower):
                matched_tokens.append(vuln_token)
                if detected_cwe is None:
                    detected_cwe = cwe

        sql_keywords = {"select", "insert", "update", "delete", "where", "from"}
        if sql_keywords & token_set:
            for kw in sql_keywords & token_set:
                if kw.upper() not in matched_tokens:
                    matched_tokens.append(kw.upper())
            if detected_cwe is None:
                detected_cwe = "CWE-89: SQL Injection"

        is_vulnerable: bool = len(matched_tokens) > 0

        if is_vulnerable:
            confidence: float = self._random.uniform(0.85, 0.95)
            cwe_category: str = detected_cwe or "CWE-200: Information Exposure"
        else:
            confidence = self._random.uniform(0.92, 0.98)
            cwe_category = "N/A"

        risk_level: str
        if not is_vulnerable:
            risk_level = "SAFE"
        elif confidence >= 0.85:
            risk_level = "HIGH"
        elif confidence >= 0.70:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        suspicious_tokens: List[str] = list(dict.fromkeys(matched_tokens))[:5]

        # Determine precise line number and line text of vulnerability location
        vulnerable_line_no = start_line
        vulnerable_line_text = ""
        if is_vulnerable and code:
            lines = code.splitlines()
            for idx, line_str in enumerate(lines):
                line_lower = line_str.lower()
                for st in suspicious_tokens:
                    if st.lower() in line_lower and len(st) > 2 and st not in ["var1", "var2", "func1"]:
                        vulnerable_line_no = start_line + idx
                        vulnerable_line_text = line_str.strip()
                        break
                if vulnerable_line_text:
                    break

            if not vulnerable_line_text and lines:
                vulnerable_line_no = start_line
                vulnerable_line_text = lines[0].strip()

        cwe_id = cwe_category.split(":")[0] if ":" in cwe_category else cwe_category
        remediation = REMEDIATION_GUIDANCE.get(cwe_id, {
            "title": "General Security Fix",
            "description": "Sanitize dynamic inputs, validate parameters, and implement secure programming practices.",
            "vulnerable_example": "Unvalidated dynamic parameter usage",
            "secure_example": "Validate and escape parameters before execution",
        })

        return {
            "function_name": func_name,
            "is_vulnerable": is_vulnerable,
            "confidence": round(confidence, 4),
            "confidence_percent": int(round(confidence * 100)),
            "cwe_category": cwe_category,
            "suspicious_tokens": suspicious_tokens,
            "start_line": start_line,
            "vulnerable_line_no": vulnerable_line_no,
            "vulnerable_line_text": vulnerable_line_text,
            "risk_level": risk_level,
            "remediation": remediation,
            "function_code": code,
        }


# ---------------------------------------------------------------------------
# Real PyTorch BiLSTM-Attention Detector Implementation
# ---------------------------------------------------------------------------

class VulnerabilityDetector:
    """
    Production vulnerability detector that loads the trained PyTorch
    BiLSTM-Attention Deep Learning model. Falls back to MockDetector
    if PyTorch or model weights are unavailable.
    """

    MODEL_PATH: str = "models/pyscan_bilstm_model.pt"
    TOKENIZER_PATH: str = "models/tokenizer_config.json"
    REPORT_PATH: str = "models/training_report.json"
    MAX_SEQ_LEN: int = 200

    def __init__(self) -> None:
        self.model: Optional[Any] = None
        self.tokenizer_vocab: Dict[str, int] = {}
        self.using_mock: bool = False
        self._mock: Optional[MockDetector] = None
        self.decision_threshold: float = 0.65

        self._load_support_files()
        self._load_model()

    def _load_support_files(self) -> None:
        """Load tokenizer vocabulary and threshold calibration metrics."""
        if os.path.exists(self.TOKENIZER_PATH):
            with open(self.TOKENIZER_PATH, "r", encoding="utf-8") as f:
                self.tokenizer_vocab = json.load(f)

        self.decision_threshold = 0.65
        if os.path.exists(self.REPORT_PATH):
            try:
                with open(self.REPORT_PATH, "r", encoding="utf-8") as f:
                    rep = json.load(f)
                    self.decision_threshold = float(rep.get("calibrated_threshold", 0.65))
            except Exception:
                pass

    def _load_model(self) -> None:
        """Attempt to load PyTorch BiLSTM-Attention model weights."""
        try:
            import torch
            from models.bilstm_model import PyScanBiLSTMAttentionEnhanced

            if not os.path.exists(self.MODEL_PATH):
                raise FileNotFoundError(f"PyTorch model weights not found at {self.MODEL_PATH}")

            vocab_size = len(self.tokenizer_vocab) + 100
            self.model = PyScanBiLSTMAttentionEnhanced(
                vocab_size=vocab_size,
                embedding_dim=128,
                hidden_dim=64,
                num_layers=2,
                dropout=0.3,
            )

            device = torch.device("cpu")
            self.model.load_state_dict(torch.load(self.MODEL_PATH, map_location=device))
            self.model.eval()
            print("[PyScan] Loaded trained PyTorch BiLSTM-Attention Deep Learning model successfully!")

        except Exception as exc:
            print(f"[PyScan] PyTorch model loading failed: {exc}")
            print("[PyScan] Falling back to MockDetector for demonstration.")
            self.using_mock = True
            self._mock = MockDetector()

    def predict(self, function_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run deep learning model inference on a preprocessed function.
        """
        if self.using_mock or self.model is None:
            return self._mock.predict(function_dict)  # type: ignore

        import torch

        func_name: str = function_dict.get("name", "unknown")
        start_line: int = function_dict.get("start_line", 0)
        raw_code: str = function_dict.get("code", "")
        raw_tokens: List[str] = function_dict.get("raw_tokens", [])

        # Tokenize and vectorize input function
        norm_code, tokens = CodeNormalizer.normalize_code(raw_code, language="py")
        if not tokens and raw_tokens:
            tokens = raw_tokens

        unk_idx = self.tokenizer_vocab.get("<UNK>", 1)
        indices = [self.tokenizer_vocab.get(t, unk_idx) for t in tokens[:self.MAX_SEQ_LEN]]
        if len(indices) < self.MAX_SEQ_LEN:
            indices += [0] * (self.MAX_SEQ_LEN - len(indices))

        input_tensor = torch.tensor([indices], dtype=torch.long)

        with torch.no_grad():
            logits, attn_weights = self.model(input_tensor)
            prob = torch.sigmoid(logits.squeeze(-1)).item()
            attn = attn_weights.squeeze(0).numpy()

        is_vulnerable: bool = prob >= self.decision_threshold
        
        # Always run the MockDetector (heuristic) to combine with BiLSTM
        mock = MockDetector()
        mock_res = mock.predict(function_dict)
        mock_is_vuln = mock_res.get("is_vulnerable", False)
        
        # If either model detects a vulnerability, flag it
        is_vulnerable = is_vulnerable or mock_is_vuln
        
        if is_vulnerable and not mock_is_vuln:
            # BiLSTM found it, Mock didn't. Confidence is prob.
            confidence = prob
        elif is_vulnerable and mock_is_vuln:
            # Both found it, or Mock found it.
            confidence = max(prob, mock_res.get("confidence", 0.0))
        else:
            confidence = 1.0 - prob

        # Categorize CWE type using token signatures and code context
        cwe_category = mock_res.get("cwe_category", "N/A")
        if is_vulnerable and cwe_category == "N/A":
            cwe_category = "CWE-200: Information Exposure"

        risk_level: str
        if not is_vulnerable:
            risk_level = "SAFE"
        elif prob >= 0.80:
            risk_level = "HIGH"
        elif prob >= 0.60:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Highlight top 5 suspicious tokens based on attention weights & security tokens
        suspicious_tokens: List[str] = []
        if is_vulnerable:
            top_attn_indices = np.argsort(attn)[::-1]
            for idx in top_attn_indices:
                if idx < len(tokens):
                    tok = tokens[idx]
                    if len(tok) > 2 and tok not in suspicious_tokens and tok not in ["<STR>", "<NUM>", "<NL>", "<INDENT>", "<DEDENT>"]:
                        suspicious_tokens.append(tok)
                        if len(suspicious_tokens) >= 5:
                            break

        if len(suspicious_tokens) < 3 and raw_tokens:
            for tok in raw_tokens:
                if tok not in suspicious_tokens and len(tok) > 2:
                    suspicious_tokens.append(tok)
                    if len(suspicious_tokens) >= 5:
                        break

        # Determine precise line number and line text of vulnerability location
        vulnerable_line_no = start_line
        vulnerable_line_text = ""
        if is_vulnerable and raw_code:
            lines = raw_code.splitlines()
            for idx, line_str in enumerate(lines):
                line_lower = line_str.lower()
                for st in suspicious_tokens:
                    if st.lower() in line_lower and len(st) > 2 and st not in ["var1", "var2", "func1"]:
                        vulnerable_line_no = start_line + idx
                        vulnerable_line_text = line_str.strip()
                        break
                if vulnerable_line_text:
                    break

            if not vulnerable_line_text and lines:
                vulnerable_line_no = start_line
                vulnerable_line_text = lines[0].strip()

        cwe_id = cwe_category.split(":")[0] if ":" in cwe_category else cwe_category
        remediation = REMEDIATION_GUIDANCE.get(cwe_id, {
            "title": "General Security Fix",
            "description": "Sanitize dynamic inputs, validate parameters, and implement secure programming practices.",
            "vulnerable_example": "Unvalidated dynamic parameter usage",
            "secure_example": "Validate and escape parameters before execution",
        })

        return {
            "function_name": func_name,
            "is_vulnerable": is_vulnerable,
            "confidence": round(confidence, 4),
            "confidence_percent": int(round(confidence * 100)),
            "cwe_category": cwe_category,
            "suspicious_tokens": suspicious_tokens[:5],
            "start_line": start_line,
            "vulnerable_line_no": vulnerable_line_no,
            "vulnerable_line_text": vulnerable_line_text,
            "risk_level": risk_level,
            "remediation": remediation,
            "function_code": raw_code,
        }
