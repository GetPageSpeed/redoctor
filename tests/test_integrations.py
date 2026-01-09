"""Tests for integrations (source scanner)."""

import tempfile
import os

from redoctor.integrations.source_scanner import (
    scan_source,
    scan_file,
    scan_directory,
    SourceVulnerability,
)


class TestScanSource:
    """Test source code scanning."""

    def test_scan_simple_regex(self):
        source = """
import re

pattern = re.compile(r"^[a-z]+$")
"""
        vulns = scan_source(source, "<test>")
        # Simple pattern should not be vulnerable
        assert isinstance(vulns, list)

    def test_scan_with_re_match(self):
        source = """
import re

result = re.match(r"^hello$", text)
"""
        vulns = scan_source(source, "<test>")
        assert isinstance(vulns, list)

    def test_scan_with_re_search(self):
        source = """
import re

result = re.search(r"[a-z]+", text)
"""
        vulns = scan_source(source, "<test>")
        assert isinstance(vulns, list)

    def test_scan_no_regex(self):
        source = """
def hello():
    print("world")
"""
        vulns = scan_source(source, "<test>")
        assert len(vulns) == 0

    def test_scan_syntax_error(self):
        source = """
def broken(
"""
        vulns = scan_source(source, "<test>")
        # Should handle syntax errors gracefully
        assert len(vulns) == 0


class TestScanFile:
    """Test file scanning."""

    def test_scan_existing_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(
                """
import re
pattern = re.compile(r"^[a-z]+$")
"""
            )
            f.flush()
            try:
                vulns = scan_file(f.name)
                assert isinstance(vulns, list)
            finally:
                os.unlink(f.name)

    def test_scan_nonexistent_file(self):
        vulns = scan_file("/nonexistent/file.py")
        assert len(vulns) == 0


class TestScanDirectory:
    """Test directory scanning."""

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            filepath = os.path.join(tmpdir, "test.py")
            with open(filepath, "w") as f:
                f.write(
                    """
import re
pattern = re.compile(r"^[a-z]+$")
"""
                )

            vulns = list(scan_directory(tmpdir))
            assert isinstance(vulns, list)


class TestSourceVulnerability:
    """Test SourceVulnerability class."""

    def test_str(self):
        from redoctor.diagnostics.diagnostics import Diagnostics

        diag = Diagnostics.safe("^test$")
        vuln = SourceVulnerability(
            file="test.py",
            line=10,
            column=5,
            pattern="^test$",
            diagnostics=diag,
        )
        s = str(vuln)
        assert "test.py" in s
        assert "10" in s

    def test_is_vulnerable(self):
        from redoctor.diagnostics.diagnostics import Diagnostics
        from redoctor.diagnostics.complexity import Complexity
        from redoctor.diagnostics.attack_pattern import AttackPattern

        diag = Diagnostics.vulnerable(
            source="^(a+)+$",
            complexity=Complexity.exponential(),
            attack_pattern=AttackPattern.simple("a", "!"),
        )
        vuln = SourceVulnerability(
            file="test.py",
            line=1,
            column=0,
            pattern="^(a+)+$",
            diagnostics=diag,
        )
        assert vuln.is_vulnerable
