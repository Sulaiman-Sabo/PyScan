"""
PyScan Preprocessing Module

Implements a 5-stage preprocessing pipeline for Python source code files
to prepare them for vulnerability detection using a BiLSTM-Attention model.

Author: PyScan Project — BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import ast
import json
import os
import re
import tokenize
from io import BytesIO
from typing import Any, Dict, List, Optional

import numpy as np


class PythonPreprocessor:
    """
    Preprocessor for Python source code vulnerability detection.

    Converts raw Python source files into tokenised numerical arrays
    suitable for deep-learning inference, while preserving semantic
    information through AST-based feature extraction.
    """

    BUILTINS: set = {
        "abs", "all", "any", "ascii", "bin", "bool", "breakpoint", "bytearray",
        "bytes", "callable", "chr", "classmethod", "compile", "complex",
        "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec",
        "filter", "float", "format", "frozenset", "getattr", "globals",
        "hasattr", "hash", "help", "hex", "id", "input", "int", "isinstance",
        "issubclass", "iter", "len", "list", "locals", "map", "max",
        "memoryview", "min", "next", "object", "oct", "open", "ord", "pow",
        "print", "property", "range", "repr", "reversed", "round", "set",
        "setattr", "slice", "sorted", "staticmethod", "str", "sum", "super",
        "tuple", "type", "vars", "zip", "__import__", "True", "False", "None",
    }

    STDLIB_MODULES: set = {
        "os", "sys", "re", "json", "hashlib", "subprocess", "sqlite3",
        "pickle", "flask", "django", "math", "random", "datetime", "time",
        "collections", "itertools", "functools", "typing", "pathlib",
        "urllib", "http", "socket", "threading", "multiprocessing",
        "logging", "unittest", "pytest", "numpy", "pandas", "requests",
        "cryptography", "bcrypt", "scapy", "paramiko", "pyyaml",
    }

    MAX_SEQ_LEN: int = 200

    def __init__(self, tokenizer_config_path: str = "models/tokenizer_config.json") -> None:
        """
        Initialise the preprocessor with a token vocabulary.

        Parameters
        ----------
        tokenizer_config_path : str
            Path to the JSON file containing the token-to-index vocabulary.
            If the file does not exist, a minimal default vocabulary is used.
        """
        self.tokenizer_config_path: str = tokenizer_config_path
        self.vocab: Dict[str, int] = self._load_vocabulary()
        self.unknown_index: int = self.vocab.get("UNKNOWN", 1)

    def _load_vocabulary(self) -> Dict[str, int]:
        """Load the token vocabulary from disk or return a minimal default."""
        if os.path.exists(self.tokenizer_config_path):
            with open(self.tokenizer_config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return self._default_vocab()

    def _default_vocab(self) -> Dict[str, int]:
        """Return a minimal default vocabulary for demonstration."""
        return {
            "<PAD>": 0, "UNKNOWN": 1, "def": 2, "return": 3, "if": 4,
            "else": 5, "for": 6, "while": 7, "import": 8, "from": 9,
            "class": 10, "try": 11, "except": 12, "raise": 13, "with": 14,
            "as": 15, "in": 16, "not": 17, "and": 18, "or": 19,
            "True": 20, "False": 21, "None": 22, "STRING_LIT": 23,
            "var1": 24, "var2": 25, "func1": 26, "func2": 27,
            "eval": 28, "exec": 29, "os": 30, "system": 31,
            "subprocess": 32, "cursor": 33, "execute": 34,
            "pickle": 35, "loads": 36, "password": 37, "secret": 38,
            "api_key": 39, "request": 40, "args": 41, "form": 42,
            "shell": 43, "hashlib": 44, "md5": 45, "sha1": 46,
            "open": 47, "print": 48, "len": 49, "range": 50,
            "input": 51, "format": 52, "join": 53, "split": 54,
            "append": 55, "get": 56, "set": 57, "list": 58,
            "dict": 59, "tuple": 60, "str": 61, "int": 62,
            "float": 63, "bool": 64, "self": 65, "__init__": 66,
            "SELECT": 67, "INSERT": 68, "UPDATE": 69, "DELETE": 70,
            "WHERE": 71, "FROM": 72, "SECRET_KEY": 73, "TOKEN": 74,
            "admin": 75, "config": 76, "DES": 77, "RC4": 78,
            "html": 79, "render": 80, "template": 81,
            "(": 82, ")": 83, ":": 84, ",": 85, ".": 86,
            "=": 87, "+": 88, "-": 89, "*": 90, "/": 91,
            "%": 92, "<": 93, ">": 94, "!": 95, "[": 96,
            "]": 97, "{": 98, "}": 99,
        }

    # Stage 1 -- Code Cleaning
    def _clean_code(self, source: str) -> str:
        """
        Remove comments, normalise indentation, and safely clean code.
        (String literal replacement removed to preserve original code for UI).
        """
        lines: List[str] = source.splitlines()
        cleaned_lines: List[str] = []

        for line in lines:
            stripped = line.split("#", 1)[0].rstrip()
            if not stripped:
                continue
            cleaned_lines.append(stripped)

        cleaned: str = "\n".join(cleaned_lines)
        cleaned = self._normalise_indentation(cleaned)
        return cleaned

    def _normalise_indentation(self, source: str) -> str:
        """Convert all indentation to multiples of 4 spaces."""
        lines: List[str] = source.splitlines()
        normalised: List[str] = []

        for line in lines:
            stripped = line.lstrip()
            if not stripped:
                normalised.append("")
                continue
            indent_str = line[:len(line) - len(stripped)]
            tab_count = indent_str.count("\t")
            space_count = indent_str.count(" ")
            total_indent = tab_count * 4 + space_count
            level = total_indent // 4
            normalised.append(" " * (level * 4) + stripped)

        return "\n".join(normalised)

    # Stage 2 -- Function & Script Extraction
    def _extract_functions(self, source: str) -> List[Dict[str, Any]]:
        """Extract all top-level function definitions or script module level code."""
        functions: List[Dict[str, Any]] = []
        lines = source.splitlines()

        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    start = node.lineno - 1
                    end = node.end_lineno if hasattr(node, "end_lineno") else start + 1
                    func_lines = lines[start:end]
                    func_code = "\n".join(func_lines)
                    functions.append({
                        "name": node.name,
                        "code": func_code,
                        "start_line": node.lineno,
                    })
        except Exception:
            pass

        # If no explicit `def` functions were found, treat the entire file/script as `<module_main>`
        if not functions and source.strip():
            functions.append({
                "name": "<module_main>",
                "code": source,
                "start_line": 1,
            })

        return functions

    # Stage 3 -- AST Feature Extraction
    def _extract_ast_features(self, func_code: str) -> str:
        """
        (Anonymization disabled per user request).
        """
        return func_code

    # Stage 4 -- Tokenisation
    def _tokenize_code(self, code: str) -> np.ndarray:
        """Tokenise code and convert to fixed-length numerical array."""
        tokens: List[str] = []

        try:
            code_bytes = code.encode("utf-8")
            for tok in tokenize.tokenize(BytesIO(code_bytes).readline):
                tok_type = tokenize.tok_name[tok.type]
                tok_str = tok.string.strip()

                if tok_type in ("NL", "NEWLINE", "INDENT", "DEDENT", "ENCODING", "COMMENT"):
                    continue
                if not tok_str:
                    continue
                tokens.append(tok_str)
        except Exception:
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\s\w]", code)

        indices: List[int] = []
        for tok in tokens:
            idx = self.vocab.get(tok, self.unknown_index)
            indices.append(idx)

        if len(indices) > self.MAX_SEQ_LEN:
            indices = indices[:self.MAX_SEQ_LEN]
        else:
            indices.extend([0] * (self.MAX_SEQ_LEN - len(indices)))

        return np.array(indices).reshape(1, self.MAX_SEQ_LEN)

    def _get_raw_tokens(self, code: str) -> List[str]:
        """Extract raw string tokens from code for display purposes."""
        tokens: List[str] = []
        try:
            code_bytes = code.encode("utf-8")
            for tok in tokenize.tokenize(BytesIO(code_bytes).readline):
                tok_type = tokenize.tok_name[tok.type]
                tok_str = tok.string.strip()
                if tok_type in ("NL", "NEWLINE", "INDENT", "DEDENT", "ENCODING", "COMMENT"):
                    continue
                if tok_str and tok_str not in ("(", ")", ":", ",", ".", "=", "+", "-", "*", "/", "%", "<", ">", "!", "[", "]", "{", "}"):
                    tokens.append(tok_str)
        except Exception:
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code)
        return tokens

    # Stage 5 -- Batch Processing
    def preprocess_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Apply the full preprocessing pipeline to every function or script in a file.

        Returns
        -------
        List[Dict[str, Any]]
            Processed function dictionaries ready for model inference.
        """
        raw_source = ""
        for enc in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
            try:
                with open(filepath, "r", encoding=enc) as f:
                    raw_source = f.read()
                break
            except Exception:
                continue

        if not raw_source:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                raw_source = f.read()

        cleaned = self._clean_code(raw_source)
        functions = self._extract_functions(cleaned)

        processed: List[Dict[str, Any]] = []
        for func in functions:
            ast_transformed = self._extract_ast_features(func["code"])
            token_array = self._tokenize_code(ast_transformed)
            raw_tokens = self._get_raw_tokens(ast_transformed)

            processed.append({
                "name": func["name"],
                "code": ast_transformed,
                "start_line": func["start_line"],
                "tokens": token_array,
                "raw_tokens": raw_tokens,
            })

        return processed

    IGNORED_DIRS = {
        ".venv", "venv", "env", "site-packages", "node_modules", ".git",
        "__pycache__", ".pytest_cache", "build", "dist", "eggs", ".egg-info",
        "venv_py", ".idea", ".vscode"
    }

    def preprocess_directory(self, root_dir: str) -> List[Dict[str, Any]]:
        """
        Recursively process all .py files in a directory, ignoring non-code vendor folders.

        Returns
        -------
        List[Dict[str, Any]]
            Processed functions with relative file path attached.
        """
        all_processed: List[Dict[str, Any]] = []
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune ignored directories in place to prevent scanning vendor bloat
            dirnames[:] = [d for d in dirnames if d.lower() not in self.IGNORED_DIRS and not d.startswith(".")]

            for filename in filenames:
                if filename.lower().endswith(".py"):
                    full_path = os.path.join(dirpath, filename)
                    rel_path = os.path.relpath(full_path, root_dir)
                    try:
                        funcs = self.preprocess_file(full_path)
                        for f in funcs:
                            f["filename"] = rel_path
                        all_processed.extend(funcs)
                    except Exception:
                        continue
        return all_processed
