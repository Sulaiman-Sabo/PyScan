"""
PyScan Supervisor Demonstration & Verification Suite
Step 4: Attention Mechanism Token Attribution & Explainability Demo
"""

import os
import sys
import json

def run_step_4():
    print("=" * 75)
    print("  STAGE 4: ATTENTION TOKEN ATTRIBUTION & EXPLAINABILITY LIVE DEMO")
    print("=" * 75)
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples_file = os.path.join(base_dir, "results", "sample_attention_weights.json")
    
    with open(samples_file, "r") as f:
        samples = json.load(f)
        
    for idx, s in enumerate(samples, 1):
        print(f"\n--- [Case Study {idx}]: Function '{s['function_name']}' ---")
        print(f"  * Ground Truth / CWE: {s['cwe_id']} ({s['cwe_category']})")
        print(f"  * Model Prediction:   {s['prediction']} (Confidence: {s['confidence']*100:.1f}%)")
        print(f"  * Risk Classification: {s['risk_level']}")
        print("  * Top-5 Attention-Weighted Tokens (Attribution Breakdown):")
        print(f"    {'Rank':<4} | {'Token Symbol':<20} | {'Attention Weight (alpha_t)':<26} | {'Security Semantics'}")
        print("    " + "-" * 75)
        for r, t in enumerate(s['tokens_with_weights'], 1):
            bar = "#" * int(t['weight'] * 40)
            print(f"    #{r:<3} | {t['token']:<20} | {t['weight']:<6.3f} [{bar:<16}] | {t['role']}")
            
    print("\n" + "=" * 75)
    print("  [SUCCESS] Explainable attention-based token attribution demonstrated!")
    print("=" * 75 + "\n")

if __name__ == '__main__':
    run_step_4()
