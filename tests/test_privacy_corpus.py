"""Synthetic regression corpus with separate signals for blocking, masking and review."""

from collections import Counter
import json
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
try:
    from review_policy import find_doubts
    from sanitize import Rejected, sanitize, scan_kind
finally:
    sys.path.pop(0)


def cases():
    return json.loads((HERE / "privacy_corpus.json").read_text(encoding="utf-8"))


def evaluate(case):
    source = case["text"]
    fmt = case.get("format", "text")
    try:
        candidate, report = sanitize(source, format=fmt)
        hints = sorted({row["kind"] for row in find_doubts(candidate, fmt)})
        output = {"changed": source != candidate, "kinds": sorted(report["occurrences"]), "hints": hints}
    except Rejected:
        output = {"changed": True, "kinds": [], "hints": []}
    try:
        output["hook"] = scan_kind(source)
    except Rejected:
        output["hook"] = "BLOCKED"
    return output


def compare(case, actual):
    expected = case["expect"]
    if expected in ("keep", "allow_with_false_alarm"):
        if actual["changed"] or actual["hook"]:
            return "false_alarm"
        return "extra_hint" if actual["hints"] else "preserved"
    if expected == "mask":
        if case["kind"] not in actual["kinds"] or not actual["hook"]:
            return "missed_sensitive"
        return "masked"
    if expected == "review":
        if actual["changed"] or actual["hook"]:
            return "false_alarm"
        return "review_hint" if actual["hints"] == [case["kind"]] else "missed_hint"
    if expected == "gap":
        return "unexpected_signal" if any(actual.values()) else "known_gap"
    raise ValueError("Unsupported expectation")


class CorpusTests(unittest.TestCase):
    def test_synthetic_cases(self):
        expected = {"keep": "preserved", "mask": "masked", "review": "review_hint",
                    "gap": "known_gap", "allow_with_false_alarm": "false_alarm"}
        fixtures = cases()
        self.assertEqual(len({case["id"] for case in fixtures}), len(fixtures))
        for case in fixtures:
            with self.subTest(case=case["id"]):
                self.assertEqual(compare(case, evaluate(case)), expected[case["expect"]])


if __name__ == "__main__":
    results = {case["id"]: compare(case, evaluate(case)) for case in cases()}
    print(json.dumps({"counts": dict(sorted(Counter(results.values()).items())), "cases": results}, indent=2))
