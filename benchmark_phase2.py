"""
benchmark_phase2.py — Document Scanner Evaluation Benchmark (Phase 2.2)

Evaluates the DocumentScanner against a 100-sample indirect prompt injection dataset
containing 40 safe documents and 60 malicious documents.

Outputs results to:
  results/benchmark_phase2_results.csv

Usage:
    python benchmark_phase2.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, List, Any

from prompt_shield.document_scanner import DocumentScanner

# ── Colors for terminal output ─────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def run_benchmark() -> None:
    # 1. Load dataset
    dataset_path = "benchmarks/indirect_prompt_injection.json"
    if not os.path.exists(dataset_path):
        print(f"{RED}{BOLD}Error: Dataset not found at {dataset_path}{RESET}")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        samples: List[Dict[str, Any]] = json.load(f)

    scanner = DocumentScanner()
    rows: List[Dict[str, Any]] = []

    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}  Document Scanner — Indirect Injection Benchmark (Phase 2.2){RESET}")
    print(f"{BOLD}{CYAN}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")

    # Metrics counters
    tp = fp = tn = fn = 0
    category_stats: Dict[str, Dict[str, int]] = {}

    for sample in samples:
        idx = sample["id"]
        category = sample["category"]
        text = sample["text"]
        is_malicious = sample["is_malicious"]

        # Run DocumentScanner
        result = scanner.scan(text)

        # A sample is flagged/caught if it is not safe (i.e. safe=False)
        flagged = not result.safe

        # Determine if classification passed/failed
        # - Malicious: passed if flagged (True Positive)
        # - Safe: passed if NOT flagged (True Negative)
        passed = (flagged == is_malicious)

        # Update confusion matrix
        if is_malicious:
            if flagged:
                tp += 1
                status = "TP (Detected)"
            else:
                fn += 1
                status = "FN (Missed)"
        else:
            if flagged:
                fp += 1
                status = "FP (False Alarm)"
            else:
                tn += 1
                status = "TN (Safe)"

        # Initialize category stats
        if category not in category_stats:
            category_stats[category] = {"total": 0, "passed": 0}
        category_stats[category]["total"] += 1
        if passed:
            category_stats[category]["passed"] += 1

        rows.append({
            "id": idx,
            "category": category,
            "text": text.replace("\n", " "),
            "expected_malicious": is_malicious,
            "actual_safe": result.safe,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "status": status,
            "passed": "✓" if passed else "✗"
        })

        icon = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
        status_color = GREEN if "TP" in status or "TN" in status else RED
        print(f"  {icon} [{idx:03d}] [{category[:30]:<30}] Score: {result.risk_score:>3} | Level: {result.risk_level:<10} | {status_color}{status:<15}{RESET}")

    # 2. Print metrics and statistics
    total_samples = len(samples)
    total_malicious = tp + fn
    total_safe = tn + fp
    accuracy = ((tp + tn) / total_samples) * 100 if total_samples else 0.0
    detection_rate = (tp / total_malicious) * 100 if total_malicious else 0.0

    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  DETAILED METRICS SUMMARY{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"  Total Samples Evaluated : {total_samples}")
    print(f"  Safe Documents          : {total_safe}")
    print(f"  Malicious Documents     : {total_malicious}")
    print(f"  --------------------------------------------------")
    print(f"  True Positives (TP)     : {GREEN}{tp}{RESET}  (Detected Attacks)")
    print(f"  False Positives (FP)    : {RED}{fp}{RESET}  (False Alarms)")
    print(f"  True Negatives (TN)     : {GREEN}{tn}{RESET}  (Correctly Allowed)")
    print(f"  False Negatives (FN)    : {RED}{fn}{RESET}  (Missed Attacks)")
    print(f"  --------------------------------------------------")
    
    color_det = GREEN if detection_rate >= 80 else (YELLOW if detection_rate >= 50 else RED)
    color_acc = GREEN if accuracy >= 80 else (YELLOW if accuracy >= 50 else RED)
    
    print(f"  Detection Rate (Recall) : {color_det}{detection_rate:.1f}%{RESET}")
    print(f"  Overall Accuracy        : {color_acc}{accuracy:.1f}%{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    # 3. Print Category Breakdown
    print(f"{BOLD}  CATEGORY BREAKDOWN{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"  {'Category':<35} | {'Total':^7} | {'Passed':^8} | {'Accuracy / Recall':^18}")
    print(f"  {'-'*68}")
    for cat, stats in sorted(category_stats.items()):
        tot = stats["total"]
        psd = stats["passed"]
        rate = (psd / tot) * 100 if tot else 0.0
        color_rate = GREEN if rate >= 80 else (YELLOW if rate >= 50 else RED)
        print(f"  {cat:<35} | {tot:^7} | {psd:^8} | {color_rate}{rate:>6.1f}%{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    # 4. Save results to CSV
    os.makedirs("results", exist_ok=True)
    csv_path = "results/benchmark_phase2_results.csv"
    with open(csv_path, "w", encoding="utf-8") as f:
        headers = ["id", "category", "text", "expected_malicious", "actual_safe", "risk_score", "risk_level", "status", "passed"]
        f.write(",".join(headers) + "\n")
        for r in rows:
            # Escape double quotes in text to prevent csv issues
            text_escaped = r["text"].replace('"', '""')
            line = [
                str(r["id"]),
                r["category"],
                f'"{text_escaped}"',
                str(r["expected_malicious"]),
                str(r["actual_safe"]),
                str(r["risk_score"]),
                r["risk_level"],
                r["status"],
                r["passed"]
            ]
            f.write(",".join(line) + "\n")

    print(f"  📊 CSV results saved to: {GREEN}{csv_path}{RESET}\n")


if __name__ == "__main__":
    run_benchmark()
