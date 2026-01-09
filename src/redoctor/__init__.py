"""
ReDoctor - A Python ReDoS (Regular Expression Denial of Service) vulnerability checker.

This library detects potential ReDoS vulnerabilities in regular expressions using
a hybrid approach combining static automata-based analysis with fuzzing.

Example usage:
    >>> from redoctor import check
    >>> result = check(r"^(a+)+$")
    >>> if result.is_vulnerable:
    ...     print(f"Vulnerable! Attack: {result.attack}")

For more control:
    >>> from redoctor import check, Config
    >>> result = check(r"^(a+)+$", config=Config(timeout=5.0))
"""

from redoctor.checker import check, check_pattern, is_safe, is_vulnerable, HybridChecker
from redoctor.config import Config, CheckerType, AccelerationMode, SeederType
from redoctor.diagnostics.complexity import Complexity, ComplexityType
from redoctor.diagnostics.diagnostics import Diagnostics, Status
from redoctor.diagnostics.attack_pattern import AttackPattern
from redoctor.diagnostics.hotspot import Hotspot
from redoctor.parser.flags import Flags
from redoctor.exceptions import RedoctorError, ParseError, TimeoutError

__version__ = "0.1.0"

__all__ = [
    # Main API
    "check",
    "check_pattern",
    "is_safe",
    "is_vulnerable",
    "HybridChecker",
    # Configuration
    "Config",
    "CheckerType",
    "AccelerationMode",
    "SeederType",
    "Flags",
    # Diagnostics
    "Diagnostics",
    "Status",
    "Complexity",
    "ComplexityType",
    "AttackPattern",
    "Hotspot",
    # Exceptions
    "RedoctorError",
    "ParseError",
    "TimeoutError",
    # Version
    "__version__",
]
