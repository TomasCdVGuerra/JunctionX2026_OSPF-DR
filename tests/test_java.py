"""Reviewed JDK and library inventory; no Java runtime is required."""
from collections import Counter
from pathlib import Path
import re

import pytest

from scanner.java_scanner import scan_file


@pytest.mark.parametrize("filename", ["SampleJdk.java", "SampleLibs.java"])
def test_java_sample_inventory(filename):
    sample = Path(__file__).with_name(filename)
    expected = Counter()
    for number, line in enumerate(sample.read_text(encoding="utf-8").splitlines(), 1):
        match = re.search(r"// EXPECT (\d+)", line)
        if match:
            expected[number] = int(match[1])
    assert expected, "Sample must declare reviewed expectations"
    findings = scan_file(str(sample), strict=True)
    assert Counter(f.line for f in findings) == expected
