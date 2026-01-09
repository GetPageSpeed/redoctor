"""Scan Python source files for regex patterns and check them for vulnerabilities."""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Iterator, Union

from redoctor.checker import check
from redoctor.diagnostics.diagnostics import Diagnostics, Status
from redoctor.config import Config


@dataclass
class SourceVulnerability:
    """A vulnerability found in source code.

    Attributes:
        file: The source file path.
        line: Line number (1-based).
        column: Column number (1-based).
        pattern: The regex pattern.
        diagnostics: The vulnerability diagnostics.
        context: The line of code containing the pattern.
    """

    file: str
    line: int
    column: int
    pattern: str
    diagnostics: Diagnostics
    context: str = ""

    def __str__(self) -> str:
        status = self.diagnostics.status.value
        return f"{self.file}:{self.line}:{self.column}: {status} - {self.pattern!r}"

    @property
    def is_vulnerable(self) -> bool:
        return self.diagnostics.is_vulnerable


class RegexFinder(ast.NodeVisitor):
    """AST visitor that finds regex patterns in Python code."""

    def __init__(self, source_lines: List[str]):
        self.patterns: List[tuple] = []  # (line, col, pattern, context)
        self.source_lines = source_lines

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to find re.compile, re.match, etc."""
        # Check for re.compile(), re.match(), re.search(), re.fullmatch(), re.findall(), re.sub()
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.func.attr
                in (
                    "compile",
                    "match",
                    "search",
                    "fullmatch",
                    "findall",
                    "finditer",
                    "sub",
                    "subn",
                    "split",
                )
            ):
                if node.args:
                    pattern_arg = node.args[0]
                    pattern = self._extract_string(pattern_arg)
                    if pattern:
                        line = node.lineno
                        col = node.col_offset
                        context = (
                            self.source_lines[line - 1]
                            if line <= len(self.source_lines)
                            else ""
                        )
                        self.patterns.append((line, col, pattern, context.strip()))

        self.generic_visit(node)

    def _extract_string(self, node: ast.expr) -> Optional[str]:
        """Extract string value from an AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Str):  # Python 3.7 compatibility
            return node.s
        if isinstance(node, ast.JoinedStr):
            # f-string - can't analyze statically
            return None
        return None


def scan_source(
    source: str, filename: str = "<string>", config: Config = None
) -> List[SourceVulnerability]:
    """Scan Python source code for regex vulnerabilities.

    Args:
        source: Python source code.
        filename: Optional filename for error messages.
        config: Optional recheck configuration.

    Returns:
        List of vulnerabilities found.
    """
    config = config or Config.quick()
    vulnerabilities: List[SourceVulnerability] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return vulnerabilities

    source_lines = source.split("\n")
    finder = RegexFinder(source_lines)
    finder.visit(tree)

    for line, col, pattern, context in finder.patterns:
        try:
            result = check(pattern, config=config)
            if result.status in (Status.VULNERABLE, Status.UNKNOWN):
                vuln = SourceVulnerability(
                    file=filename,
                    line=line,
                    column=col,
                    pattern=pattern,
                    diagnostics=result,
                    context=context,
                )
                vulnerabilities.append(vuln)
        except Exception:  # nosec B110 - intentional: skip unparseable patterns
            pass

    return vulnerabilities


def scan_file(
    filepath: "Union[str, Path]", config: Config = None
) -> List[SourceVulnerability]:
    """Scan a Python file for regex vulnerabilities.

    Args:
        filepath: Path to the Python file.
        config: Optional recheck configuration.

    Returns:
        List of vulnerabilities found.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        return []

    try:
        source = filepath.read_text(encoding="utf-8")
    except Exception:
        return []

    return scan_source(source, str(filepath), config)


def scan_directory(
    directory: "Union[str, Path]",
    recursive: bool = True,
    config: Config = None,
) -> Iterator[SourceVulnerability]:
    """Scan a directory for Python files with regex vulnerabilities.

    Args:
        directory: Path to the directory.
        recursive: Whether to scan recursively.
        config: Optional recheck configuration.

    Yields:
        SourceVulnerability for each vulnerability found.
    """
    directory = Path(directory)
    pattern = "**/*.py" if recursive else "*.py"

    for filepath in directory.glob(pattern):
        vulnerabilities = scan_file(filepath, config)
        for vuln in vulnerabilities:
            yield vuln
