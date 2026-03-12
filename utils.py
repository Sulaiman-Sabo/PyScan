"""
Utility functions for the vulnerability detection system
"""
import hashlib
import json
import re
import ast
from typing import List, Tuple, Dict, Any
import numpy as np

def sha256_hash(text: str) -> str:
    """Generate SHA-256 hash for deduplication"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def clean_code(code: str) -> str:
    """Stage 1: Code Cleaning and Normalization"""
    # Remove single-line comments
    code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
    
    # Remove multi-line strings (docstrings)
    code = re.sub(r"'''{3}[\s\S]*?'''{3}", '', code)
    code = re.sub(r'"""{3}[\s\S]*?"""{3}', '', code)
    
    # Replace string literals with placeholder
    code = re.sub(r'["\'][^"\']*["\']', 'STRING_LIT', code)
    
    # Replace numeric literals
    code = re.sub(r'\b\d+\b', 'NUM_LIT', code)
    
    # Normalize whitespace
    lines = code.split('\n')
    cleaned_lines = []
    for line in lines:
        line = line.replace('\t', '    ')
        line = line.rstrip()
        if line.strip():
            cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)

def is_valid_python(code: str) -> bool:
    """Check if code is syntactically valid Python"""
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False

def extract_functions_from_code(code: str) -> List[Dict[str, Any]]:
    """Extract function definitions from Python code using AST"""
    if not is_valid_python(code):
        return []
    
    try:
        tree = ast.parse(code)
        functions = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                start_line = node.lineno - 1
                end_line = node.end_lineno
                func_code = '\n'.join(code.split('\n')[start_line:end_line])
                
                functions.append({
                    'name': node.name,
                    'code': func_code,
                    'start_line': start_line + 1,
                    'end_line': end_line,
                    'args': [arg.arg for arg in node.args.args]
                })
        
        return functions
    except Exception as e:
        print(f"Error extracting functions: {e}")
        return []

def normalize_variable_names(code: str) -> str:
    """Stage 3: Variable Substitution"""
    try:
        tree = ast.parse(code)
        var_counter = 0
        func_counter = 0
        name_mapping = {}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if node.id in ['True', 'False', 'None', 'self', 'cls']:
                    continue
                if node.id not in name_mapping:
                    name_mapping[node.id] = f'var{var_counter}'
                    var_counter += 1
            elif isinstance(node, ast.FunctionDef):
                if node.name not in name_mapping:
                    name_mapping[node.name] = f'func{func_counter}'
                    func_counter += 1
        
        normalized_code = code
        for old_name, new_name in name_mapping.items():
            normalized_code = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, normalized_code)
        
        return normalized_code
    except:
        return code

def tokenize_code(code: str) -> List[str]:
    """Stage 4: Tokenization using Python's tokenize module"""
    import io
    import tokenize
    
    tokens = []
    try:
        code_bytes = io.BytesIO(code.encode('utf-8'))
        for tok in tokenize.tokenize(code_bytes.readline):
            if tok.type in [tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NEWLINE, tokenize.NL]:
                continue
            tokens.append(tok.string)
    except:
        tokens = code.split()
    
    return tokens

def pad_sequences(sequences: List[List[int]], maxlen: int, padding_value: int = 0) -> np.ndarray:
    """Pad sequences to fixed length"""
    padded = np.full((len(sequences), maxlen), padding_value, dtype=np.int32)
    
    for i, seq in enumerate(sequences):
        if len(seq) > maxlen:
            padded[i] = seq[:maxlen]
        else:
            padded[i, :len(seq)] = seq
    
    return padded

def save_json(data: Any, filepath: str):
    """Save data to JSON file"""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def load_json(filepath: str) -> Any:
    """Load data from JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)

def get_top_attention_tokens(tokens: List[str], attention_weights: np.ndarray, top_k: int = 5) -> List[Tuple[str, float]]:
    """Extract top-k tokens by attention weight for localization"""
    if len(attention_weights.shape) > 1:
        attention_weights = attention_weights.flatten()
    
    top_indices = np.argsort(attention_weights)[-top_k:][::-1]
    
    results = []
    for idx in top_indices:
        if idx < len(tokens):
            results.append((tokens[idx], float(attention_weights[idx])))
    
    return results