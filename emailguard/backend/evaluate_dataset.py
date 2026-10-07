"""Run a small synthetic corpus through the rule engine and report prototype metrics."""
from __future__ import annotations

import time
from collections import Counter
from pathlib import Path

from app.service import analyze_email_bytes

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
CASES = [
    ("safe_newsletter.eml", "SAFE"),
    ("attachment_metadata.eml", "SAFE"),
    ("suspicious_but_uncertain.eml", "SUSPICIOUS"),
    ("lookalike_phishing.eml", "MALICIOUS"),
]
LABELS = ("SAFE", "SUSPICIOUS", "MALICIOUS")


def main() -> None:
    matrix: Counter[tuple[str, str]] = Counter()
    timings: list[float] = []
    rows: list[tuple[str, str, str, int, float]] = []
    for filename, expected in CASES:
        raw = (FIXTURE_DIR / filename).read_bytes()
        start = time.perf_counter()
        report = analyze_email_bytes(raw, filename)
        elapsed_ms = (time.perf_counter() - start) * 1000
        predicted = report["classification"]
        matrix[(expected, predicted)] += 1
        timings.append(elapsed_ms)
        rows.append((filename, expected, predicted, report["safety_score"], elapsed_ms))

    print("EmailGuard · synthetic corpus evaluation")
    print("Prototype assessment only; these small fixtures are not a representative benchmark.\n")
    print(f"{'Fixture':34} {'Expected':12} {'Predicted':12} {'Safety':>7} {'Time (ms)':>11}")
    print("-" * 82)
    for filename, expected, predicted, safety, elapsed in rows:
        print(f"{filename:34} {expected:12} {predicted:12} {safety:>7} {elapsed:>11.2f}")

    total = len(CASES)
    accuracy = sum(matrix[(label, label)] for label in LABELS) / total if total else 0
    expected_malicious = sum(1 for _, expected in CASES if expected == "MALICIOUS")
    detected_malicious = sum(matrix[("MALICIOUS", label)] for label in LABELS if label != "SAFE")
    safe_count = sum(1 for _, expected in CASES if expected == "SAFE")
    false_positives = sum(matrix[("SAFE", label)] for label in LABELS if label != "SAFE")
    print("\nConfusion matrix (rows = expected, columns = predicted)")
    print(f"{'':14}" + "".join(f"{label:>14}" for label in LABELS))
    for expected in LABELS:
        print(f"{expected:14}" + "".join(f"{matrix[(expected, predicted)]:>14}" for predicted in LABELS))
    print(f"\nAccuracy: {accuracy:.1%}")
    print(f"Malicious detection rate: {detected_malicious / expected_malicious:.1%}" if expected_malicious else "Malicious detection rate: n/a")
    print(f"False-positive rate on synthetic SAFE cases: {false_positives / safe_count:.1%}" if safe_count else "False-positive rate: n/a")
    print(f"Mean analysis time: {sum(timings) / len(timings):.2f} ms" if timings else "Mean analysis time: n/a")


if __name__ == "__main__":
    main()
