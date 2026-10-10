"""
PyScan Command Line Interface (CLI) Security Scanner

Enables developers to scan massive local codebases, enterprise repositories, and
multi-gigabyte projects directly from their terminal with zero HTTP upload size limits.

Usage:
    python pyscan_cli.py --path /path/to/codebase
    python pyscan_cli.py --path /path/to/codebase --output report.json

Author: PyScan Project -- BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List

sys.path.insert(0, os.path.abspath("."))
from detector import VulnerabilityDetector
from preprocessor import PythonPreprocessor


def run_cli_scan(target_path: str, output_report: str = None) -> None:
    """
    Run local CLI security scan on a file or folder target.
    """
    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path):
        print(f"[-] Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    print("==================================================================")
    print(" PyScan Enterprise Command Line Vulnerability Scanner")
    print("==================================================================")
    print(f"[*] Target Path    : {target_path}")
    print(f"[*] Scanner Mode   : Local High-Scale CLI Engine")

    preprocessor = PythonPreprocessor()
    detector = VulnerabilityDetector()

    start_time = time.time()

    if os.path.isdir(target_path):
        print("[*] Preprocessing directory tree (skipping vendor & non-code folders)...")
        functions = preprocessor.preprocess_directory(target_path)
    else:
        print("[*] Preprocessing target Python file...")
        functions = preprocessor.preprocess_file(target_path)

    total_functions = len(functions)
    print(f"[+] Found {total_functions:,} Python functions across target.")

    if total_functions == 0:
        print("[!] No Python functions detected in target.")
        return

    print("[*] Executing Deep Learning Model Inference...")
    results: List[Dict[str, Any]] = []
    vulnerable_count = 0
    cwe_summary: Dict[str, int] = {}

    for idx, fn in enumerate(functions, start=1):
        pred = detector.predict(fn)
        if pred["is_vulnerable"]:
            vulnerable_count += 1
            cwe = pred["cwe_category"]
            cwe_summary[cwe] = cwe_summary.get(cwe, 0) + 1

        results.append({
            "filename": fn.get("filename", os.path.basename(target_path)),
            "function_name": pred["function_name"],
            "start_line": pred["start_line"],
            "is_vulnerable": pred["is_vulnerable"],
            "risk_level": pred["risk_level"],
            "confidence_percent": pred["confidence_percent"],
            "cwe_category": pred["cwe_category"],
            "suspicious_tokens": pred["suspicious_tokens"],
        })

    scan_time = round(time.time() - start_time, 2)
    vulnerability_rate = (vulnerable_count / total_functions) * 100 if total_functions > 0 else 0.0

    if vulnerability_rate == 0:
        security_grade = "A+"
    elif vulnerability_rate <= 10:
        security_grade = "B"
    elif vulnerability_rate <= 25:
        security_grade = "C"
    elif vulnerability_rate <= 40:
        security_grade = "D"
    else:
        security_grade = "F"

    print("\n==================================================================")
    print(" SCAN RESULTS SUMMARY")
    print("==================================================================")
    print(f"  • Security Grade        : {security_grade}")
    print(f"  • Total Functions Scanned: {total_functions:,}")
    print(f"  • Vulnerable Functions  : {vulnerable_count:,} ({vulnerability_rate:.1f}%)")
    print(f"  • Clean / Safe Functions: {total_functions - vulnerable_count:,}")
    print(f"  • Execution Time        : {scan_time:.2f} seconds")
    print("==================================================================")

    if cwe_summary:
        print("\n[*] Detected Vulnerability Distribution:")
        for cwe, count in sorted(cwe_summary.items(), key=lambda x: x[1], reverse=True):
            print(f"    - {cwe}: {count:,}")

    if vulnerable_count > 0:
        print("\n[*] Detailed Vulnerability Findings:")
        for r in results:
            if r["is_vulnerable"]:
                print(f"  [!] {r['filename']} | {r['function_name']}() (Line {r['start_line']})")
                print(f"      Risk: {r['risk_level']} | Conf: {r['confidence_percent']}% | Category: {r['cwe_category']}")
                print(f"      Tokens: {', '.join(r['suspicious_tokens'])}\n")

    if output_report:
        report_data = {
            "target": target_path,
            "security_grade": security_grade,
            "total_functions": total_functions,
            "vulnerable_functions": vulnerable_count,
            "execution_time_seconds": scan_time,
            "findings": results,
        }
        with open(output_report, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] Saved detailed scan report to '{output_report}'")


def main() -> None:
    parser = argparse.ArgumentParser(description="PyScan CLI Security Scanner for Large Codebases")
    parser.add_argument("--path", "-p", required=True, help="Path to local target Python file or codebase directory")
    parser.add_argument("--output", "-o", required=False, help="Optional output JSON report path")
    args = parser.parse_args()

    run_cli_scan(args.path, args.output)


if __name__ == "__main__":
    main()
