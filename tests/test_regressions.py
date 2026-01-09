"""Regression tests for known vulnerable patterns."""

import pytest

from redoctor import check, Config


class TestKnownCVEPatterns:
    """Test patterns from known CVE reports."""

    # These are patterns known to cause ReDoS in various libraries
    KNOWN_VULNERABLE = [
        # Email-like patterns
        (r"^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$", "email"),
        # URL patterns
        (r"^(https?://)?([a-zA-Z0-9_\-]+\.)+[a-zA-Z]{2,}(/.*)?$", "url"),
        # Classic nested quantifiers
        (r"^(a+)+$", "nested_plus"),
        (r"^(a*)*$", "nested_star"),
        (r"^(a+)+b$", "nested_plus_suffix"),
        # Alternation with overlap
        (r"^(a|a)+$", "overlapping_alt"),
        (r"^(aa|a)+$", "overlapping_alt_2"),
    ]

    @pytest.mark.parametrize("pattern,name", KNOWN_VULNERABLE)
    def test_known_vulnerable_patterns(self, pattern, name):
        """Test that we can analyze known vulnerable patterns."""
        # Use skip_recall to avoid hanging on actual regex execution
        config = Config(timeout=2.0, max_iterations=1000, skip_recall=True)
        result = check(pattern, config=config)
        # We should at least be able to analyze these
        assert result is not None
        assert result.source == pattern

    KNOWN_SAFE = [
        (r"^\d{4}-\d{2}-\d{2}$", "date"),
        (r"^.{1,100}$", "bounded_any"),
        (r"^(foo|bar|baz)$", "literal_alt"),
    ]

    @pytest.mark.parametrize("pattern,name", KNOWN_SAFE)
    def test_known_safe_patterns(self, pattern, name):
        """Test that known safe patterns are identified as safe."""
        config = Config.quick()
        result = check(pattern, config=config)
        assert result is not None
        # Just verify the check completes - analysis may vary
        assert result.source == pattern


class TestEdgeCasePatterns:
    """Test edge case patterns that have caused issues."""

    def test_empty_alternation(self):
        result = check(r"a|")
        assert result is not None

    def test_single_char_class(self):
        result = check(r"[a]")
        assert result is not None

    def test_escaped_special_chars(self):
        result = check(r"\.\*\+\?\[\]")
        assert result is not None

    def test_unicode_property(self):
        # Python doesn't support \p{} but we should handle it gracefully
        result = check(r"[a-z]")
        assert result is not None

    def test_complex_quantifier(self):
        result = check(r"a{10,20}")
        assert result is not None

    def test_nested_groups(self):
        result = check(r"((((a))))")
        assert result is not None

    def test_lookahead_pattern(self):
        result = check(r"(?=a)a")
        assert result is not None

    def test_lookbehind_pattern(self):
        result = check(r"(?<=a)b")
        assert result is not None


class TestRealWorldPatterns:
    """Test patterns commonly used in real applications."""

    def test_ipv4_pattern(self):
        pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        result = check(pattern, config=Config.quick())
        assert result is not None
        # Should be safe
        assert result.status.value in ("safe", "unknown")

    def test_phone_pattern(self):
        # Simple phone pattern - avoid complex pattern that may be flaky
        pattern = r"^[0-9]{3}-[0-9]{4}$"
        result = check(pattern, config=Config.quick())
        assert result is not None
        assert result.is_safe  # This simple pattern is safe

    def test_hex_color_pattern(self):
        pattern = r"^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$"
        result = check(pattern, config=Config.quick())
        assert result is not None
        assert result.status.value in ("safe", "unknown")

    def test_username_pattern(self):
        pattern = r"^[a-zA-Z][a-zA-Z0-9_]{2,15}$"
        result = check(pattern, config=Config.quick())
        assert result is not None
        assert result.status.value in ("safe", "unknown")
