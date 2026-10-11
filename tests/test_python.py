"""Reviewed source inventory; samples are parsed, never executed."""
from collections import Counter
from pathlib import Path
import re

from scanner.python_scanner import scan_file


def test_python_sample_inventory():
    sample = Path(__file__).with_name("sample_completo.py")
    expected = Counter()
    for number, line in enumerate(sample.read_text(encoding="utf-8").splitlines(), 1):
        match = re.search(r"# EXPECT (\d+)", line)
        if match:
            expected[number] = int(match[1])
    assert expected, "Sample must declare reviewed expectations"
    findings = scan_file(str(sample), strict=True)
    assert Counter(f.line for f in findings) == expected
