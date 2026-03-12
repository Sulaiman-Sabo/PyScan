"""
Configuration for Python Vulnerability Detection System
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
UPLOADS_DIR = BASE_DIR / "uploads"

# Create directories if they don't exist
for dir_path in [DATA_DIR, MODELS_DIR, UPLOADS_DIR]:
    dir_path.mkdir(exist_ok=True)

# Model Configuration (CPU-Optimized)
MODEL_CONFIG = {
    'max_sequence_length': 200,
    'embedding_dim': 128,
    'vocab_size': 10000,
    'bilstm_units_1': 128,
    'bilstm_units_2': 64,
    'dropout_rate': 0.3,
    'attention_dim': 128,
    'batch_size': 32,
    'epochs': 20,
    'learning_rate': 0.001,
    'validation_split': 0.2,
}

# CWE Categories (11 types)
CWE_CATEGORIES = {
    89: "SQL Injection",
    79: "Cross-site Scripting (XSS)",
    352: "Cross-Site Request Forgery (CSRF)",
    78: "OS Command Injection",
    434: "Insecure File Upload",
    22: "Directory Traversal",
    798: "Hard-coded Credentials",
    327: "Insecure Cryptographic Implementation",
    319: "Insecure Network Connection",
    732: "Insecure File Permissions",
    502: "Insecure Deserialization"
}

# Preprocessing Configuration
PREPROCESS_CONFIG = {
    'min_token_frequency': 2,
    'max_functions_per_file': 100,
    'max_file_size_mb': 1,
    'string_placeholder': 'STRING_LIT',
    'number_placeholder': 'NUM_LIT',
    'unknown_token': '<UNK>',
    'pad_token': '<PAD>',
}

# Flask Configuration
FLASK_CONFIG = {
    'secret_key': os.environ.get('SECRET_KEY', 'dev-key-change-in-production'),
    'max_content_length': 1 * 1024 * 1024,
    'debug': True,
    'host': '127.0.0.1',
    'port': 5000,
}

# File paths
MODEL_PATH = MODELS_DIR / "bilstm_attention_model.h5"
TOKENIZER_PATH = MODELS_DIR / "tokenizer_config.json"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.json"
WORD2VEC_PATH = MODELS_DIR / "word2vec_model.bin"