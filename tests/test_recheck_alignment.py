"""Tests to verify 1:1 alignment with recheck's behavior.

This file contains tests specifically designed to verify that redoctor's
behavior matches recheck's AutomatonChecker and documents known differences.

Reference: https://github.com/MakeNowJust-Labo/recheck
Tests derived from:
- modules/recheck-core/shared/src/test/scala/codes/quine/labs/recheck/automaton/AutomatonCheckerSuite.scala
- modules/recheck-core/shared/src/test/scala/codes/quine/labs/recheck/ReDoSSuite.scala
- modules/recheck-core/shared/src/test/scala/codes/quine/labs/recheck/fuzz/FuzzCheckerSuite.scala
"""

import pytest

from redoctor.parser.parser import parse
from redoctor.parser.flags import Flags
from redoctor.parser.ast import has_end_anchor, requires_continuation
from redoctor.automaton.eps_nfa_builder import build_eps_nfa
from redoctor.automaton.complexity_analyzer import ComplexityAnalyzer
from redoctor.diagnostics.complexity import ComplexityType


def analyze(pattern_str: str, flags: Flags = None) -> ComplexityType:
    """Analyze a pattern and return its complexity type."""
    pattern = parse(pattern_str, flags)
    eps_nfa = build_eps_nfa(pattern)
    pattern_has_end_anchor = has_end_anchor(pattern.node)
    pattern_requires_continuation = requires_continuation(pattern.node)
    analyzer = ComplexityAnalyzer(
        eps_nfa,
        has_end_anchor=pattern_has_end_anchor,
        requires_continuation=pattern_requires_continuation,
    )
    complexity, _ = analyzer.analyze()
    return complexity.type


# =============================================================================
# EXACT MATCHES WITH RECHECK
# These tests should produce EXACTLY the same result as recheck
# =============================================================================


class TestExactMatchesWithRecheck:
    """Patterns where we expect EXACT behavior match with recheck."""

    # From AutomatonCheckerSuite: "constant"
    CONSTANT_EXACT = [
        (r"^$", "empty anchored"),
        (r"^foo$", "literal anchored"),
        (r"^((fi|bu)z{2}){1,2}$", "bounded repeat with alternation"),
    ]

    # From AutomatonCheckerSuite: "linear" (subset that we match exactly)
    LINEAR_EXACT = [
        (r"a*", "simple star"),
    ]

    # From AutomatonCheckerSuite: "exponential"
    EXPONENTIAL_EXACT = [
        (r"^(a|a)*$", "overlapping alternation"),
        (r"^((a)*)*$", "nested star groups"),
        (r"^(a|b|ab)*$", "overlapping with concatenation"),
        (r"^(aa|b|aab)*$", "longer overlapping patterns"),
    ]

    # From AutomatonCheckerSuite: "polynomial" (we may report exponential)
    POLYNOMIAL_DETECTED = [
        (r"^.*a.*a$", "double wildcard"),
        (r"^.*a.*a.*a$", "triple wildcard"),
    ]

    @pytest.mark.parametrize("pattern,name", CONSTANT_EXACT)
    def test_constant_exact_match(self, pattern, name):
        """Constant patterns - EXACT match with recheck (SAFE)."""
        result = analyze(pattern)
        assert result == ComplexityType.SAFE, f"{pattern} ({name}) should be SAFE"

    @pytest.mark.parametrize("pattern,name", LINEAR_EXACT)
    def test_linear_exact_match(self, pattern, name):
        """Linear patterns - EXACT match with recheck (SAFE)."""
        result = analyze(pattern)
        assert result == ComplexityType.SAFE, f"{pattern} ({name}) should be SAFE"

    @pytest.mark.parametrize("pattern,name", EXPONENTIAL_EXACT)
    def test_exponential_exact_match(self, pattern, name):
        """Exponential patterns - EXACT match with recheck (EXPONENTIAL)."""
        result = analyze(pattern)
        assert result == ComplexityType.EXPONENTIAL, (
            f"{pattern} ({name}) should be EXPONENTIAL"
        )

    @pytest.mark.parametrize("pattern,name", POLYNOMIAL_DETECTED)
    def test_polynomial_detected(self, pattern, name):
        """Polynomial patterns - detected as vulnerable (may be EXPONENTIAL instead)."""
        result = analyze(pattern)
        assert result in (
            ComplexityType.POLYNOMIAL,
            ComplexityType.EXPONENTIAL,
        ), f"{pattern} ({name}) should be POLYNOMIAL or EXPONENTIAL"


# =============================================================================
# CONSERVATIVE FALSE POSITIVES (DOCUMENTED DIFFERENCES)
# Patterns where we are MORE conservative than recheck (acceptable)
# =============================================================================


class TestConservativeFalsePositives:
    """Patterns where redoctor is more conservative than recheck.

    These are cases where recheck's NFAwLA look-ahead pruning eliminates
    false ambiguity, but our simpler detection still flags them.

    This is ACCEPTABLE behavior - we prefer false positives over false negatives.
    """

    def test_nested_star_same_char(self):
        """(a*)* - recheck says LINEAR, we may say EXPONENTIAL.

        Recheck's NFAwLA look-ahead pruning recognizes that both levels
        consume the same 'a' characters, eliminating false paths.

        Our simpler epsilon-path counting sees structural ambiguity.
        """
        result = analyze(r"(a*)*")
        # We accept either - ours is conservative
        assert result in (ComplexityType.SAFE, ComplexityType.EXPONENTIAL)

    def test_empty_group_in_repeat(self):
        """^(a()*a)*$ - recheck says LINEAR, we may say EXPONENTIAL.

        The empty group () matches zero characters, so it's effectively
        a no-op. Recheck recognizes this and reports LINEAR.
        """
        result = analyze(r"^(a()*a)*$")
        # We accept either
        assert result in (ComplexityType.SAFE, ComplexityType.EXPONENTIAL)

    def test_dotall_overlapping_dots(self):
        """^(?:.|.)*$ with dotall - recheck says LINEAR, we may say EXPONENTIAL.

        With dotall, both dots match the exact same character set (everything).
        Recheck's look-ahead pruning recognizes no real ambiguity.
        """
        result = analyze(r"^(?:.|.)*$", Flags(dotall=True))
        # We accept either
        assert result in (ComplexityType.SAFE, ComplexityType.EXPONENTIAL)

    def test_word_boundary_in_repeat(self):
        """^([a:]|\\b)*$ - recheck says LINEAR, we may say EXPONENTIAL.

        Word boundaries \\b are zero-width assertions that don't consume input.
        However, they create multiple epsilon paths to the same character
        transition, which our simpler detection flags as potential EDA.

        Recheck's NFAwLA look-ahead pruning recognizes these are redundant
        paths and eliminates them.
        """
        result = analyze(r"^([a:]|\b)*$")
        # Accept either - our detection may be more conservative
        assert result in (ComplexityType.SAFE, ComplexityType.EXPONENTIAL)


# =============================================================================
# CASE INSENSITIVE FLAG TESTS
# =============================================================================


class TestCaseInsensitivePatterns:
    """Tests for patterns with case-insensitive flag."""

    def test_overlapping_with_case_insensitive(self):
        """^(a|B|Ab)*$ with 'i' flag - recheck says EXPONENTIAL.

        With case-insensitive:
        - 'a' matches 'a', 'A'
        - 'B' matches 'b', 'B'
        - 'Ab' matches 'ab', 'Ab', 'aB', 'AB'

        "ab" can match as 'a' then 'B' OR as 'Ab' -> ambiguity!
        """
        result = analyze(r"^(a|B|Ab)*$", Flags(ignore_case=True))
        assert result == ComplexityType.EXPONENTIAL

    def test_simple_case_insensitive_is_safe(self):
        """^[a-z]+$ with 'i' flag - should still be SAFE.

        Case-insensitive doesn't introduce ambiguity for simple patterns.
        """
        result = analyze(r"^[a-z]+$", Flags(ignore_case=True))
        assert result == ComplexityType.SAFE

    def test_word_nonword_case_insensitive(self):
        """^(\\w|\\W)*$ with 'i' flag - recheck says LINEAR.

        \\w and \\W together cover all characters, so no overlap = no ambiguity.
        """
        result = analyze(r"^(\w|\W)*$", Flags(ignore_case=True))
        assert result == ComplexityType.SAFE


# =============================================================================
# MULTILINE FLAG TESTS
# =============================================================================


class TestMultilinePatterns:
    """Tests for patterns with multiline flag."""

    def test_anchors_with_multiline(self):
        """^.+$ with multiline flag - each line is matched."""
        result = analyze(r"^.+$", Flags(multiline=True))
        assert result == ComplexityType.SAFE

    def test_overlapping_with_multiline(self):
        """^(a|a)+$ with multiline flag - still EXPONENTIAL."""
        result = analyze(r"^(a|a)+$", Flags(multiline=True))
        assert result == ComplexityType.EXPONENTIAL


# =============================================================================
# CRITICAL SAFE PATTERNS (NO FALSE POSITIVES)
# =============================================================================


class TestCriticalSafePatterns:
    """Patterns that MUST be SAFE - false positives here break trust."""

    CRITICAL_SAFE = [
        # Simple quantifiers
        (r"^a+$", "simple plus"),
        (r"^a*$", "simple star"),
        (r"a+", "unanchored plus"),
        # Character classes
        (r"^[a-z]+$", "lowercase class"),
        (r"^[A-Za-z0-9]+$", "alphanumeric"),
        (r"^\d+$", "digits"),
        (r"^\w+$", "word chars"),
        (r"^\s+$", "whitespace"),
        # Disjoint alternation
        (r"^(a|b)+$", "disjoint a|b"),
        (r"^(a|b|c)+$", "disjoint a|b|c"),
        (r"^([a-c]|[x-z])+$", "disjoint ranges"),
        (r"^(foo|bar)+$", "disjoint literals"),
        # Bounded quantifiers
        (r"^a{1,10}$", "bounded"),
        (r"^.{1,100}$", "bounded any"),
        (r"^a{5}$", "exact repeat"),
        # Common real-world patterns
        (r"^\d{4}-\d{2}-\d{2}$", "date YYYY-MM-DD"),
        (r"^\d{2}/\d{2}/\d{4}$", "date DD/MM/YYYY"),
        (r"^[a-zA-Z][a-zA-Z0-9_]{2,15}$", "username"),
        (r"^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$", "hex color"),
    ]

    @pytest.mark.parametrize("pattern,name", CRITICAL_SAFE)
    def test_critical_safe(self, pattern, name):
        """These patterns MUST be SAFE - no false positives allowed."""
        result = analyze(pattern)
        assert result == ComplexityType.SAFE, (
            f"CRITICAL FALSE POSITIVE: {pattern} ({name}) flagged as {result}"
        )


# =============================================================================
# CRITICAL VULNERABLE PATTERNS (NO FALSE NEGATIVES)
# =============================================================================


class TestCriticalVulnerablePatterns:
    """Patterns that MUST be detected - false negatives are security issues."""

    CRITICAL_VULNERABLE = [
        # Classic nested quantifiers
        (r"^(a+)+$", "nested plus"),
        (r"^(a+)+b$", "nested plus with suffix"),
        (r"^([a-z]+)+$", "nested class plus"),
        (r"^([^@]+)+@", "email-like"),
        # Overlapping alternation
        (r"^(a|a)*$", "overlapping a|a"),
        (r"^(ab|a|b)*$", "overlapping with concat"),
        (r"^(a|b|ab)*$", "overlapping a|b|ab"),
        (r"^(aa|a|aaa)*$", "overlapping lengths"),
        # Nested groups
        (r"^((a)*)*$", "nested star groups"),
        (r"^((a+)*)+$", "nested plus and star"),
        (r"^(([a-z]+)*)+$", "nested class groups"),
    ]

    @pytest.mark.parametrize("pattern,name", CRITICAL_VULNERABLE)
    def test_critical_vulnerable(self, pattern, name):
        """These patterns MUST be detected as vulnerable."""
        result = analyze(pattern)
        assert result in (
            ComplexityType.EXPONENTIAL,
            ComplexityType.POLYNOMIAL,
        ), f"CRITICAL FALSE NEGATIVE: {pattern} ({name}) not detected! Got {result}"


# =============================================================================
# EDGE CASES AND BOUNDARY CONDITIONS
# =============================================================================


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_pattern(self):
        """Empty pattern should be safe."""
        assert analyze(r"") == ComplexityType.SAFE

    def test_single_char(self):
        """Single character patterns should be safe."""
        assert analyze(r"a") == ComplexityType.SAFE
        assert analyze(r".") == ComplexityType.SAFE
        assert analyze(r"\d") == ComplexityType.SAFE

    def test_anchors_only(self):
        """Anchor-only patterns should be safe."""
        assert analyze(r"^$") == ComplexityType.SAFE
        assert analyze(r"^") == ComplexityType.SAFE
        assert analyze(r"$") == ComplexityType.SAFE

    def test_optional_patterns(self):
        """Optional patterns should generally be safe."""
        assert analyze(r"^a?$") == ComplexityType.SAFE
        assert analyze(r"^a?b?c?$") == ComplexityType.SAFE

    def test_very_long_literal(self):
        """Long literal patterns should be safe."""
        pattern = "^" + "a" * 100 + "$"
        assert analyze(pattern) == ComplexityType.SAFE

    def test_many_alternations_disjoint(self):
        """Many disjoint alternations should be safe."""
        pattern = r"^(a|b|c|d|e|f|g|h|i|j)+$"
        assert analyze(pattern) == ComplexityType.SAFE

    def test_many_alternations_overlapping(self):
        """Many overlapping alternations should be detected."""
        pattern = r"^(a|a|a|a|a)+$"
        assert analyze(pattern) == ComplexityType.EXPONENTIAL


# =============================================================================
# BACKREFERENCE TESTS
# =============================================================================


class TestBackreferences:
    """Tests for patterns with backreferences.

    Backreferences are not fully supported by automaton-based analysis,
    so these may need fuzz-based detection.
    """

    def test_simple_backreference(self):
        """Simple backreference pattern analysis."""
        # This may or may not be detected depending on implementation
        result = analyze(r"^(a+)\1$")
        # Just verify it doesn't crash
        assert result in (
            ComplexityType.SAFE,
            ComplexityType.POLYNOMIAL,
            ComplexityType.EXPONENTIAL,
        )

    def test_backreference_in_star(self):
        """Backreference inside star - potential for issues."""
        # Patterns like ^((?:a|b)*)\1$ can cause ReDoS
        result = analyze(r"^((?:a|b)*)\1$")
        # Just verify it doesn't crash
        assert result in (
            ComplexityType.SAFE,
            ComplexityType.POLYNOMIAL,
            ComplexityType.EXPONENTIAL,
        )


# =============================================================================
# PERFORMANCE SANITY
# =============================================================================


class TestPerformance:
    """Ensure analysis completes in reasonable time."""

    PATTERNS_TO_ANALYZE = [
        r"^a+$",
        r"^[a-z]+$",
        r"^(a+)+$",
        r"^(a|a)*$",
        r"^(a|b|ab)*$",
        r"^.*a.*a$",
        r"^\d{4}-\d{2}-\d{2}$",
        r"^[a-zA-Z][a-zA-Z0-9_]{2,15}$",
        r"^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$",
    ]

    @pytest.mark.parametrize("pattern", PATTERNS_TO_ANALYZE)
    def test_analysis_completes(self, pattern):
        """Analysis should complete without timeout for common patterns."""
        # This will fail if analysis takes too long (pytest timeout)
        result = analyze(pattern)
        assert result is not None
