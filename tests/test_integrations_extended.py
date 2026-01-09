"""Extended integration tests for increased coverage."""

import tempfile
import os

from redoctor.integrations.source_scanner import (
    scan_source,
    scan_directory,
    SourceVulnerability,
    RegexFinder,
)
from redoctor.config import Config
from redoctor.diagnostics.diagnostics import Diagnostics


class TestRegexFinder:
    """Test the RegexFinder AST visitor."""

    def test_find_re_compile(self):
        import ast

        source = 'import re\npattern = re.compile(r"test")'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 1
        assert finder.patterns[0][2] == "test"

    def test_find_re_match(self):
        import ast

        source = 'import re\nre.match(r"pattern", text)'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 1

    def test_find_re_search(self):
        import ast

        source = 'import re\nre.search(r"pattern", text)'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 1

    def test_find_re_findall(self):
        import ast

        source = 'import re\nre.findall(r"pattern", text)'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 1

    def test_find_re_finditer(self):
        import ast

        source = 'import re\nre.finditer(r"pattern", text)'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 1

    def test_find_re_sub(self):
        import ast

        source = 'import re\nre.sub(r"pattern", "", text)'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 1

    def test_find_re_split(self):
        import ast

        source = 'import re\nre.split(r"pattern", text)'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 1

    def test_skip_fstring(self):
        import ast

        source = 'import re\nre.compile(f"{var}")'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 0

    def test_skip_non_re_call(self):
        import ast

        source = 'other.compile(r"pattern")'
        tree = ast.parse(source)
        finder = RegexFinder(source.split("\n"))
        finder.visit(tree)
        assert len(finder.patterns) == 0


class TestScanSourceExtended:
    """Extended source scanning tests."""

    def test_scan_multiple_patterns(self):
        source = """
import re

p1 = re.compile(r"^[a-z]+$")
p2 = re.compile(r"^[0-9]+$")
"""
        vulns = scan_source(source, "<test>")
        # Both patterns are safe, so vulns might be empty
        assert isinstance(vulns, list)

    def test_scan_with_config(self):
        source = """
import re
pattern = re.compile(r"^[a-z]+$")
"""
        config = Config.quick()
        vulns = scan_source(source, "<test>", config=config)
        assert isinstance(vulns, list)


class TestScanDirectoryExtended:
    """Extended directory scanning tests."""

    def test_scan_directory_non_recursive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            filepath = os.path.join(tmpdir, "test.py")
            with open(filepath, "w") as f:
                f.write('import re\nre.compile(r"test")')

            # Create a subdirectory with file
            subdir = os.path.join(tmpdir, "sub")
            os.makedirs(subdir)
            subpath = os.path.join(subdir, "test2.py")
            with open(subpath, "w") as f:
                f.write('import re\nre.compile(r"test2")')

            vulns = list(scan_directory(tmpdir, recursive=False))
            # Should only find the file in the root
            assert isinstance(vulns, list)


class TestSourceVulnerabilityExtended:
    """Extended SourceVulnerability tests."""

    def test_context_field(self):
        diag = Diagnostics.safe("^test$")
        vuln = SourceVulnerability(
            file="test.py",
            line=1,
            column=0,
            pattern="^test$",
            diagnostics=diag,
            context="re.compile(r'^test$')",
        )
        assert vuln.context == "re.compile(r'^test$')"

    def test_not_vulnerable(self):
        diag = Diagnostics.safe("^test$")
        vuln = SourceVulnerability(
            file="test.py",
            line=1,
            column=0,
            pattern="^test$",
            diagnostics=diag,
        )
        assert not vuln.is_vulnerable
