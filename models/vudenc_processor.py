"""
VUDENC Data Extraction, Cleaning, Normalization & Merging Processor

Extracts code snippets from all 7 VUDENC dataset categories, normalizes tokens,
merges with CVEFixes Python samples, performs stratified splitting, and exports
NumPy matrices for model training.

Author: PyScan Project -- BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.abspath("."))
from models.dataset import CodeNormalizer, CVEFixesProcessor

CWE_MAPPINGS = {
    "plain_command_injection": "CWE-78: OS Command Injection",
    "plain_open_redirect": "CWE-601: Open Redirect",
    "plain_path_disclosure": "CWE-22: Path Traversal / Information Exposure",
    "plain_remote_code_execution": "CWE-502: Insecure Deserialization / Code Execution",
    "plain_sql": "CWE-89: SQL Injection",
    "plain_xsrf": "CWE-352: Cross-Site Request Forgery (CSRF)",
    "plain_xss": "CWE-79: Cross-Site Scripting (XSS)",
}


class VUDENCProcessor:
    """Processor for extracting, normalizing, and splitting VUDENC datasets."""

    MAX_SEQ_LEN: int = 200

    def __init__(
        self,
        vudenc_dir: str = "VUDENC_Dataset",
        output_dir: str = "VUDENC_Dataset/processed",
        vocab_path: str = "models/tokenizer_config.json",
    ) -> None:
        self.vudenc_dir = vudenc_dir
        self.output_dir = output_dir
        self.vocab_path = vocab_path
        self.vocab: Dict[str, int] = {}

    def extract_vudenc_raw(self) -> pd.DataFrame:
        """
        Extract all badparts (vulnerable=1) and goodparts (safe=0) code snippets
        from the 7 plain_* JSON files in VUDENC.
        """
        records = []
        plain_files = [
            "plain_command_injection",
            "plain_open_redirect",
            "plain_path_disclosure",
            "plain_remote_code_execution",
            "plain_sql",
            "plain_xsrf",
            "plain_xss",
        ]

        print("[*] Extracting raw code snippets from 7 VUDENC plain_* datasets...")

        for fname in plain_files:
            fpath = os.path.join(self.vudenc_dir, fname)
            if not os.path.exists(fpath):
                print(f"[!] Warning: File {fpath} missing, skipping...")
                continue

            cwe_label = CWE_MAPPINGS.get(fname, "CWE-Other")
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            category_snippets = 0
            for repo_url, commits in data.items():
                for commit_hash, commit_info in commits.items():
                    files_dict = commit_info.get("files", {})
                    for file_path, file_data in files_dict.items():
                        changes = file_data.get("changes", [])
                        for change in changes:
                            # Extract badparts (Vulnerable = 1)
                            for bad_lines in change.get("badparts", []):
                                if isinstance(bad_lines, list):
                                    bad_text = "\n".join(str(l) for l in bad_lines)
                                else:
                                    bad_text = str(bad_lines)
                                if len(bad_text.strip()) > 10:
                                    records.append({
                                        "code_raw": bad_text,
                                        "label": 1,
                                        "safety": "vulnerable",
                                        "cwe": cwe_label,
                                        "source_category": fname,
                                    })
                                    category_snippets += 1

                            # Extract goodparts (Safe = 0)
                            for good_lines in change.get("goodparts", []):
                                if isinstance(good_lines, list):
                                    good_text = "\n".join(str(l) for l in good_lines)
                                else:
                                    good_text = str(good_lines)
                                if len(good_text.strip()) > 10:
                                    records.append({
                                        "code_raw": good_text,
                                        "label": 0,
                                        "safety": "safe",
                                        "cwe": cwe_label,
                                        "source_category": fname,
                                    })
                                    category_snippets += 1

            print(f"    - Extracted {category_snippets:,} snippets from {fname}")

        raw_df = pd.DataFrame(records)
        print(f"[+] Total raw VUDENC snippets extracted: {len(raw_df):,}")
        return raw_df

    def process_and_normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean whitespace, strip comments, mask literals, tokenize, and de-duplicate.
        """
        print("[*] Cleaning and normalizing code snippets...")
        
        # 1. Basic text cleaning
        df["code_clean"] = df["code_raw"].apply(CodeNormalizer.clean_text)
        df = df[df["code_clean"].str.len() > 10].copy()

        # 2. De-duplication and contradictory label resolution
        code_label_counts = df.groupby("code_clean")["label"].nunique()
        ambiguous = code_label_counts[code_label_counts > 1].index
        if len(ambiguous) > 0:
            print(f"[*] Removing {len(ambiguous):,} ambiguous code samples with contradictory labels...")
            df = df[~df["code_clean"].isin(ambiguous)].copy()

        df = df.drop_duplicates(subset=["code_clean", "label"]).copy()

        # 3. Tokenization & Literal Masking
        norm_codes = []
        token_lists = []
        token_lengths = []

        for _, row in df.iterrows():
            norm_code, tokens = CodeNormalizer.normalize_code(row["code_clean"], language="py")
            norm_codes.append(norm_code)
            token_lists.append(tokens)
            token_lengths.append(len(tokens))

        df["normalized_code"] = norm_codes
        df["tokens"] = token_lists
        df["token_length"] = token_lengths

        df = df[df["token_length"] > 0].copy()
        print(f"[+] Cleaned & normalized VUDENC dataset: {len(df):,} samples")
        return df

    def merge_with_cvefixes(self, vudenc_df: pd.DataFrame) -> pd.DataFrame:
        """
        Merge normalized VUDENC dataset with normalized CVEFixes Python dataset.
        """
        cvefixes_path = "CVEFixes_Dataset/processed/py_cleaned_normalized.csv"
        if not os.path.exists(cvefixes_path):
            print("[!] CVEFixes processed dataset not found, generating...")
            cve_proc = CVEFixesProcessor()
            cve_proc.process_and_save_all()

        print(f"[*] Merging with CVEFixes dataset from {cvefixes_path}...")
        cve_df = pd.read_csv(cvefixes_path)

        # Prepare matching columns
        cve_df["cwe"] = "CVEFixes-Vulnerability"
        cve_df["source_category"] = "cvefixes"
        
        # Tokenize CVEFixes normalized code if token column missing
        token_lists = []
        token_lengths = []
        for _, row in cve_df.iterrows():
            _, tokens = CodeNormalizer.normalize_code(str(row["normalized_code"]), language="py")
            token_lists.append(tokens)
            token_lengths.append(len(tokens))

        cve_df["tokens"] = token_lists
        cve_df["token_length"] = token_lengths
        cve_df = cve_df[cve_df["token_length"] > 0].copy()

        combined_df = pd.concat([vudenc_df, cve_df], ignore_index=True)
        
        # Final de-duplication across combined datasets
        combined_df = combined_df.drop_duplicates(subset=["normalized_code", "label"]).copy()
        print(f"[+] Combined Dataset (VUDENC + CVEFixes): {len(combined_df):,} samples")
        return combined_df

    def process_all_and_export(
        self,
        output_dir: str = "combined_dataset/processed",
        vocab_size: int = 15000,
    ) -> Dict[str, Any]:
        """
        End-to-end pipeline: Extract VUDENC $\to$ Normalize $\to$ Merge CVEFixes $\to$ Split $\to$ Export.
        """
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)

        # 1. Extract and normalize VUDENC
        raw_vudenc = self.extract_vudenc_raw()
        norm_vudenc = self.process_and_normalize(raw_vudenc)

        # Export VUDENC standalone CSV
        vudenc_csv_path = os.path.join(self.output_dir, "vudenc_cleaned_normalized.csv")
        norm_vudenc[["normalized_code", "safety", "label", "cwe", "token_length"]].to_csv(vudenc_csv_path, index=False)
        print(f"[+] Saved VUDENC standalone dataset to {vudenc_csv_path}")

        # 2. Merge VUDENC + CVEFixes
        combined_df = self.merge_with_cvefixes(norm_vudenc)
        combined_csv_path = os.path.join(output_dir, "combined_cvefixes_vudenc.csv")
        combined_df[["normalized_code", "safety", "label", "cwe", "source_category", "token_length"]].to_csv(combined_csv_path, index=False)
        print(f"[+] Saved Combined dataset CSV to {combined_csv_path}")

        # 3. Build comprehensive Token Vocabulary
        print(f"[*] Building master vocabulary from combined corpus...")
        cve_proc = CVEFixesProcessor(vocab_path=self.vocab_path)
        cve_proc.build_vocabulary(combined_df["tokens"].tolist(), max_vocab_size=vocab_size)

        # 4. Stratified Train (70%) / Val (15%) / Test (15%) Split
        train_df, val_df, test_df = cve_proc.split_dataset(combined_df, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)

        # Save CSV splits
        train_df[["normalized_code", "safety", "label", "cwe", "token_length"]].to_csv(os.path.join(output_dir, "train.csv"), index=False)
        val_df[["normalized_code", "safety", "label", "cwe", "token_length"]].to_csv(os.path.join(output_dir, "val.csv"), index=False)
        test_df[["normalized_code", "safety", "label", "cwe", "token_length"]].to_csv(os.path.join(output_dir, "test.csv"), index=False)

        # Also save copies into VUDENC_Dataset/processed/
        train_df[["normalized_code", "safety", "label", "cwe", "token_length"]].to_csv(os.path.join(self.output_dir, "train.csv"), index=False)
        val_df[["normalized_code", "safety", "label", "cwe", "token_length"]].to_csv(os.path.join(self.output_dir, "val.csv"), index=False)
        test_df[["normalized_code", "safety", "label", "cwe", "token_length"]].to_csv(os.path.join(self.output_dir, "test.csv"), index=False)

        # 5. Vectorize into padded NumPy matrices
        X_train = cve_proc.pad_sequences(train_df["tokens"].tolist())
        y_train = train_df["label"].to_numpy(dtype=np.int32)

        X_val = cve_proc.pad_sequences(val_df["tokens"].tolist())
        y_val = val_df["label"].to_numpy(dtype=np.int32)

        X_test = cve_proc.pad_sequences(test_df["tokens"].tolist())
        y_test = test_df["label"].to_numpy(dtype=np.int32)

        # Save matrices to combined_dataset/processed/
        np.save(os.path.join(output_dir, "X_train.npy"), X_train)
        np.save(os.path.join(output_dir, "y_train.npy"), y_train)
        np.save(os.path.join(output_dir, "X_val.npy"), X_val)
        np.save(os.path.join(output_dir, "y_val.npy"), y_val)
        np.save(os.path.join(output_dir, "X_test.npy"), X_test)
        np.save(os.path.join(output_dir, "y_test.npy"), y_test)

        # Save matrices to VUDENC_Dataset/processed/
        np.save(os.path.join(self.output_dir, "X_train.npy"), X_train)
        np.save(os.path.join(self.output_dir, "y_train.npy"), y_train)
        np.save(os.path.join(self.output_dir, "X_val.npy"), X_val)
        np.save(os.path.join(self.output_dir, "y_val.npy"), y_val)
        np.save(os.path.join(self.output_dir, "X_test.npy"), X_test)
        np.save(os.path.join(self.output_dir, "y_test.npy"), y_test)

        print(f"[+] Exported NumPy Matrices:")
        print(f"    - X_train: {X_train.shape}, y_train: {y_train.shape}")
        print(f"    - X_val:   {X_val.shape}, y_val:   {y_val.shape}")
        print(f"    - X_test:  {X_test.shape}, y_test:  {y_test.shape}")

        # 6. Generate Summary JSON
        summary: Dict[str, Any] = {
            "vudenc_standalone_samples": int(len(norm_vudenc)),
            "combined_samples": int(len(combined_df)),
            "max_sequence_length": self.MAX_SEQ_LEN,
            "vocabulary_size": len(cve_proc.vocab),
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
            "category_distribution": combined_df["cwe"].value_counts().to_dict(),
        }

        with open(os.path.join(output_dir, "dataset_summary_combined.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        with open(os.path.join(self.output_dir, "dataset_summary.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"[+] Summary saved to {output_dir}/dataset_summary_combined.json")
        return summary


if __name__ == "__main__":
    processor = VUDENCProcessor()
    processor.process_all_and_export()
