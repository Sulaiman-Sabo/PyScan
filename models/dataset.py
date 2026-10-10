"""
PyScan Dataset Processing & Loading Module

Implements data cleaning, fixing, normalization, vocabulary construction,
stratified train/val/test splitting, and matrix vectorization for the CVEFixes
vulnerability dataset.

Author: PyScan Project -- BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import ast
import json
import os
import re
import tokenize
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


class CodeNormalizer:
    """Normalizes raw code snippets by removing noise and standardizing tokens."""

    STRING_REGEX = re.compile(r'(\"\"\"[\s\S]*?\"\"\"|\'\'\'[\s\S]*?\'\'\'|\"[^\n\"\\]*(?:\\.[^\n\"\\]*)*\"|\'[^\n\'\\]*(?:\\.[^\n\'\\]*)*\')')
    NUMBER_REGEX = re.compile(r'\b\d+(\.\d+)?([eE][+-]?\d+)?\b')
    PYTHON_COMMENT_REGEX = re.compile(r'#.*')
    C_COMMENT_REGEX = re.compile(r'//.*|/\*[\s\S]*?\*/')

    @staticmethod
    def clean_text(text: str) -> str:
        """Fix line endings, strip non-printable ASCII control characters."""
        if not isinstance(text, str):
            return ""
        # Standardize newlines
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        # Remove non-printable control characters except tabs/newlines
        text = "".join(ch for ch in text if ch in "\n\t" or (32 <= ord(ch) <= 126) or ord(ch) > 127)
        return text.strip()

    @classmethod
    def strip_comments(cls, code: str, language: str = "py") -> str:
        """Strip single-line and multi-line comments based on language."""
        lang = language.lower().strip()
        if lang in ["py", "python"]:
            # Strip python comments
            lines = []
            for line in code.split("\n"):
                stripped_line = cls.PYTHON_COMMENT_REGEX.sub("", line)
                if stripped_line.strip():
                    lines.append(stripped_line)
            return "\n".join(lines)
        else:
            # Strip C / Java / PHP / JS style comments
            code = cls.C_COMMENT_REGEX.sub("", code)
            return "\n".join(line for line in code.split("\n") if line.strip())

    @classmethod
    def normalize_literals(cls, code: str) -> str:
        """Replace raw strings with <STR> and numbers with <NUM>."""
        code = cls.STRING_REGEX.sub("<STR>", code)
        code = cls.NUMBER_REGEX.sub("<NUM>", code)
        return code

    @classmethod
    def tokenize(cls, code: str, language: str = "py") -> List[str]:
        """
        Tokenize normalized code into a sequence of meaningful semantic tokens.
        """
        lang = language.lower().strip()
        if lang in ["py", "python"]:
            try:
                tokens = []
                tokens_gen = tokenize.tokenize(BytesIO(code.encode("utf-8")).readline)
                for tok in tokens_gen:
                    if tok.type in (tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NL, tokenize.COMMENT):
                        continue
                    if tok.type == tokenize.NEWLINE:
                        tokens.append("<NL>")
                    elif tok.type == tokenize.INDENT:
                        tokens.append("<INDENT>")
                    elif tok.type == tokenize.DEDENT:
                        tokens.append("<DEDENT>")
                    elif tok.type == tokenize.STRING:
                        tokens.append("<STR>")
                    elif tok.type == tokenize.NUMBER:
                        tokens.append("<NUM>")
                    else:
                        tok_str = tok.string.strip()
                        if tok_str:
                            tokens.append(tok_str)
                if tokens:
                    return tokens
            except Exception:
                pass

        # Fallback regex-based tokenizer for generic code / syntax recovery
        raw_tokens = re.findall(r'<[A-Z_]+>|\b\w+\b|[^\s\w]', code)
        return [t for t in raw_tokens if t.strip()]

    @classmethod
    def normalize_code(cls, code: str, language: str = "py") -> Tuple[str, List[str]]:
        """
        Perform full normalization pipeline on code.
        
        Returns
        -------
        Tuple[str, List[str]]
            Normalized code string and list of tokens.
        """
        cleaned = cls.clean_text(code)
        if not cleaned:
            return "", []
        no_comments = cls.strip_comments(cleaned, language=language)
        normalized_str = cls.normalize_literals(no_comments)
        tokens = cls.tokenize(normalized_str, language=language)
        return normalized_str, tokens


class CVEFixesProcessor:
    """Processes, cleans, normalizes, and splits the CVEFixes dataset."""

    MAX_SEQ_LEN: int = 200

    def __init__(self, vocab_path: str = "models/tokenizer_config.json") -> None:
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.vocab_path = os.path.join(self.project_root, vocab_path)
        self.vocab: Dict[str, int] = {}
        self.inv_vocab: Dict[int, str] = {}

    def clean_dataset(self, csv_path: str) -> pd.DataFrame:
        """
        Load, validate, fix, and de-duplicate the raw CVEFixes dataset.
        """
        csv_path = os.path.join(self.project_root, csv_path) if not os.path.isabs(csv_path) else csv_path
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Dataset not found at {csv_path}")

        print(f"[*] Loading raw dataset from {csv_path}...")
        df = pd.read_csv(csv_path, low_memory=False)
        initial_count = len(df)
        print(f"[*] Initial records: {initial_count:,}")

        # 1. Drop missing code, language, or safety
        df = df.dropna(subset=["code", "safety"]).copy()
        df["language"] = df["language"].fillna("Other").astype(str).str.strip().str.lower()
        df["code"] = df["code"].astype(str)

        # 2. Clean whitespace and remove empty records
        df["code_clean"] = df["code"].apply(CodeNormalizer.clean_text)
        df = df[df["code_clean"].str.len() > 10].copy()

        # 3. Standardize safety labels: vulnerable -> 1, safe -> 0
        df["safety"] = df["safety"].astype(str).str.strip().str.lower()
        df = df[df["safety"].isin(["vulnerable", "safe"])].copy()
        df["label"] = (df["safety"] == "vulnerable").astype(int)

        # 4. De-duplicate identical code records
        # If identical code has contradictory safety labels, drop both to prevent ambiguity
        code_label_counts = df.groupby("code_clean")["label"].nunique()
        ambiguous_code = code_label_counts[code_label_counts > 1].index
        if len(ambiguous_code) > 0:
            print(f"[*] Removing {len(ambiguous_code):,} ambiguous code samples with conflicting labels...")
            df = df[~df["code_clean"].isin(ambiguous_code)].copy()

        df = df.drop_duplicates(subset=["code_clean", "label"]).copy()
        print(f"[*] Cleaned records: {len(df):,} (Removed {initial_count - len(df):,} invalid/duplicate rows)")
        return df

    def normalize_dataset(self, df: pd.DataFrame, language: Optional[str] = "py") -> pd.DataFrame:
        """
        Normalize code text and extract token sequences for the target language.
        """
        if language:
            target_langs = [language.lower(), "python"] if language.lower() in ["py", "python"] else [language.lower()]
            df = df[df["language"].isin(target_langs)].copy()
            print(f"[*] Filtered for language '{language}': {len(df):,} records")

        print("[*] Normalizing code and extracting tokens...")
        normalized_texts = []
        token_lists = []
        token_lengths = []

        for _, row in df.iterrows():
            norm_code, tokens = CodeNormalizer.normalize_code(row["code_clean"], language=row["language"])
            normalized_texts.append(norm_code)
            token_lists.append(tokens)
            token_lengths.append(len(tokens))

        df["normalized_code"] = normalized_texts
        df["tokens"] = token_lists
        df["token_length"] = token_lengths

        # Filter out records that produced no tokens
        df = df[df["token_length"] > 0].copy()
        print(f"[*] Normalization complete. Valid tokenized records: {len(df):,}")
        return df

    def build_vocabulary(self, token_lists: List[List[str]], max_vocab_size: int = 10000) -> Dict[str, int]:
        """
        Build and save token vocabulary from the tokenized corpus.
        """
        from collections import Counter
        print(f"[*] Building vocabulary (max_size={max_vocab_size})...")
        
        counter = Counter()
        for toks in token_lists:
            counter.update(toks)

        # Reserve special tokens
        vocab = {
            "<PAD>": 0,
            "<UNK>": 1,
            "<STR>": 2,
            "<NUM>": 3,
            "<NL>": 4,
            "<INDENT>": 5,
            "<DEDENT>": 6,
        }

        # Add most common tokens
        for token, _ in counter.most_common(max_vocab_size - len(vocab)):
            if token not in vocab:
                vocab[token] = len(vocab)

        self.vocab = vocab
        self.inv_vocab = {v: k for k, v in vocab.items()}

        os.makedirs(os.path.dirname(os.path.abspath(self.vocab_path)), exist_ok=True)
        with open(self.vocab_path, "w", encoding="utf-8") as f:
            json.dump(vocab, f, indent=2)

        print(f"[*] Vocabulary constructed with {len(vocab):,} unique tokens saved to {self.vocab_path}")
        return vocab

    def pad_sequences(self, token_lists: List[List[str]], max_seq_len: Optional[int] = None) -> np.ndarray:
        """
        Convert token sequences to fixed-length integer index matrices.
        """
        max_len = max_seq_len or self.MAX_SEQ_LEN
        unk_idx = self.vocab.get("<UNK>", 1)
        matrix = np.zeros((len(token_lists), max_len), dtype=np.int32)

        for i, toks in enumerate(token_lists):
            indices = [self.vocab.get(t, unk_idx) for t in toks[:max_len]]
            matrix[i, :len(indices)] = indices

        return matrix

    @staticmethod
    def split_dataset(
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        random_state: int = 42,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Perform stratified train/val/test split preserving label balance.
        """
        assert abs((train_ratio + val_ratio + test_ratio) - 1.0) < 1e-5, "Ratios must sum to 1.0"

        # First split: Train vs (Val + Test)
        val_test_ratio = val_ratio + test_ratio
        train_df, val_test_df = train_test_split(
            df,
            test_size=val_test_ratio,
            random_state=random_state,
            stratify=df["label"],
        )

        # Second split: Val vs Test
        test_sub_ratio = test_ratio / val_test_ratio
        val_df, test_df = train_test_split(
            val_test_df,
            test_size=test_sub_ratio,
            random_state=random_state,
            stratify=val_test_df["label"],
        )

        print(f"[*] Stratified Split:")
        print(f"    Train: {len(train_df):,} records ({len(train_df)/len(df)*100:.1f}%) | "
              f"Vuln: {train_df['label'].sum():,} / Safe: {(train_df['label'] == 0).sum():,}")
        print(f"    Val:   {len(val_df):,} records ({len(val_df)/len(df)*100:.1f}%) | "
              f"Vuln: {val_df['label'].sum():,} / Safe: {(val_df['label'] == 0).sum():,}")
        print(f"    Test:  {len(test_df):,} records ({len(test_df)/len(df)*100:.1f}%) | "
              f"Vuln: {test_df['label'].sum():,} / Safe: {(test_df['label'] == 0).sum():,}")

        return train_df.copy(), val_df.copy(), test_df.copy()

    def process_and_save_all(
        self,
        raw_csv_path: str = "CVEFixes_Dataset/CVEFixes.csv",
        output_dir: str = "CVEFixes_Dataset/processed",
        language: str = "py",
    ) -> Dict[str, Any]:
        """
        Execute end-to-end cleaning, normalization, vocabulary building, splitting,
        and binary matrix export.
        """
        output_dir = os.path.join(self.project_root, output_dir) if not os.path.isabs(output_dir) else output_dir
        os.makedirs(output_dir, exist_ok=True)

        # 1. Clean raw dataset
        cleaned_full_df = self.clean_dataset(raw_csv_path)
        cleaned_full_path = os.path.join(output_dir, "cvefixes_cleaned_full.csv")
        cleaned_full_df[["code_clean", "language", "safety", "label"]].to_csv(
            cleaned_full_path, index=False
        )
        print(f"[+] Saved full cleaned dataset to {cleaned_full_path}")

        # 2. Normalize target language subset
        lang_df = self.normalize_dataset(cleaned_full_df, language=language)
        lang_clean_path = os.path.join(output_dir, f"{language}_cleaned_normalized.csv")
        
        # Save readable normalized CSV without token lists
        csv_export_df = lang_df[["code_clean", "normalized_code", "language", "safety", "label", "token_length"]].copy()
        csv_export_df.to_csv(lang_clean_path, index=False)
        print(f"[+] Saved normalized dataset to {lang_clean_path}")

        # 3. Build Token Vocabulary
        self.build_vocabulary(lang_df["tokens"].tolist(), max_vocab_size=10000)

        # 4. Stratified Train / Val / Test Split
        train_df, val_df, test_df = self.split_dataset(lang_df, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)

        # Save CSV splits
        train_csv_path = os.path.join(output_dir, "train.csv")
        val_csv_path = os.path.join(output_dir, "val.csv")
        test_csv_path = os.path.join(output_dir, "test.csv")

        train_df[["normalized_code", "safety", "label", "token_length"]].to_csv(train_csv_path, index=False)
        val_df[["normalized_code", "safety", "label", "token_length"]].to_csv(val_csv_path, index=False)
        test_df[["normalized_code", "safety", "label", "token_length"]].to_csv(test_csv_path, index=False)

        # 5. Vectorize into padded NumPy matrices
        X_train = self.pad_sequences(train_df["tokens"].tolist())
        y_train = train_df["label"].to_numpy(dtype=np.int32)

        X_val = self.pad_sequences(val_df["tokens"].tolist())
        y_val = val_df["label"].to_numpy(dtype=np.int32)

        X_test = self.pad_sequences(test_df["tokens"].tolist())
        y_test = test_df["label"].to_numpy(dtype=np.int32)

        np.save(os.path.join(output_dir, "X_train.npy"), X_train)
        np.save(os.path.join(output_dir, "y_train.npy"), y_train)
        np.save(os.path.join(output_dir, "X_val.npy"), X_val)
        np.save(os.path.join(output_dir, "y_val.npy"), y_val)
        np.save(os.path.join(output_dir, "X_test.npy"), X_test)
        np.save(os.path.join(output_dir, "y_test.npy"), y_test)
        print(f"[+] Saved NumPy matrices (X_train: {X_train.shape}, X_val: {X_val.shape}, X_test: {X_test.shape})")

        # 6. Generate Summary JSON
        summary: Dict[str, Any] = {
            "raw_samples": int(len(cleaned_full_df)),
            "language": language,
            "target_samples": int(len(lang_df)),
            "vocabulary_size": len(self.vocab),
            "max_sequence_length": self.MAX_SEQ_LEN,
            "splits": {
                "train": {
                    "total": int(len(train_df)),
                    "vulnerable": int(train_df["label"].sum()),
                    "safe": int((train_df["label"] == 0).sum()),
                },
                "val": {
                    "total": int(len(val_df)),
                    "vulnerable": int(val_df["label"].sum()),
                    "safe": int((val_df["label"] == 0).sum()),
                },
                "test": {
                    "total": int(len(test_df)),
                    "vulnerable": int(test_df["label"].sum()),
                    "safe": int((test_df["label"] == 0).sum()),
                },
            },
            "token_length_stats": {
                "mean": float(lang_df["token_length"].mean()),
                "median": float(lang_df["token_length"].median()),
                "max": int(lang_df["token_length"].max()),
                "min": int(lang_df["token_length"].min()),
            },
        }

        summary_path = os.path.join(output_dir, "dataset_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Saved processing summary to {summary_path}")

        return summary


def load_dataset(processed_dir: str = "CVEFixes_Dataset/processed") -> Tuple[Tuple[np.ndarray, np.ndarray], Tuple[np.ndarray, np.ndarray], Tuple[np.ndarray, np.ndarray]]:
    """
    Convenience function to load ready-to-train NumPy splits.

    Returns
    -------
    (X_train, y_train), (X_val, y_val), (X_test, y_test)
    """
    X_train = np.load(os.path.join(processed_dir, "X_train.npy"))
    y_train = np.load(os.path.join(processed_dir, "y_train.npy"))
    X_val = np.load(os.path.join(processed_dir, "X_val.npy"))
    y_val = np.load(os.path.join(processed_dir, "y_val.npy"))
    X_test = np.load(os.path.join(processed_dir, "X_test.npy"))
    y_test = np.load(os.path.join(processed_dir, "y_test.npy"))
    return (X_train, y_train), (X_val, y_val), (X_test, y_test)


if __name__ == "__main__":
    processor = CVEFixesProcessor()
    processor.process_and_save_all()
