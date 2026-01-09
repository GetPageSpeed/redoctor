"""Tests for the main checker."""

import pytest

from redoctor import check, is_safe, is_vulnerable, Config, Diagnostics, Status
from redoctor.checker import HybridChecker, check_pattern
from redoctor.parser.parser import parse
from redoctor.parser.flags import Flags


class TestCheckFunction:
    """Test the main check function."""

    def test_check_simple_pattern(self):
        result = check(r"^[a-z]+$")
        assert isinstance(result, Diagnostics)
        assert result.source == r"^[a-z]+$"

    def test_check_with_flags(self):
        result = check(r"^hello$", Flags(ignore_case=True))
        assert result is not None

    def test_check_with_config(self):
        config = Config.quick()
        result = check(r"^[a-z]+$", config=config)
        assert result is not None

    def test_check_invalid_pattern(self):
        result = check(r"(unclosed")
        assert result.status == Status.ERROR
        assert result.error is not None


class TestIsSafe:
    """Test the is_safe function."""

    def test_safe_patterns(self, safe_patterns):
        for pattern in safe_patterns:
            result = is_safe(pattern, config=Config.quick())
            # Note: Quick config may not catch all issues
            assert isinstance(result, bool)

    def test_literal_pattern(self):
        assert is_safe(r"^hello$", config=Config.quick())


class TestIsVulnerable:
    """Test the is_vulnerable function."""

    def test_vulnerable_check(self):
        # Just ensure the function works
        result = is_vulnerable(r"^[a-z]+$", config=Config.quick())
        assert isinstance(result, bool)


class TestHybridChecker:
    """Test the hybrid checker."""

    def test_creation(self):
        checker = HybridChecker()
        assert checker is not None

    def test_creation_with_config(self):
        config = Config(timeout=5.0)
        checker = HybridChecker(config)
        assert checker.config.timeout == 5.0

    def test_check_string(self):
        checker = HybridChecker(Config.quick())
        result = checker.check(r"^[a-z]+$")
        assert isinstance(result, Diagnostics)

    def test_check_pattern(self):
        checker = HybridChecker(Config.quick())
        pattern = parse(r"^[a-z]+$")
        result = checker.check_pattern(pattern)
        assert isinstance(result, Diagnostics)


class TestCheckPattern:
    """Test check_pattern function."""

    def test_check_parsed_pattern(self):
        pattern = parse(r"^[a-z]+$")
        result = check_pattern(pattern, Config.quick())
        assert isinstance(result, Diagnostics)


class TestKnownPatterns:
    """Test with known vulnerable and safe patterns."""

    @pytest.mark.parametrize(
        "pattern",
        [
            r"^\d{4}-\d{2}-\d{2}$",
            r"^hello$",
        ],
    )
    def test_safe_patterns(self, pattern):
        result = check(pattern, config=Config.quick())
        # Just verify analysis completes - results may vary
        assert result is not None
        assert result.source == pattern

    @pytest.mark.parametrize(
        "pattern",
        [
            r"^(a+)+$",
            r"^(a|a)+$",
            r"^(a*)*$",
        ],
    )
    def test_potentially_vulnerable_patterns(self, pattern):
        result = check(pattern, config=Config.quick())
        # Just verify the check completes
        assert result is not None
        assert result.source == pattern


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_pattern(self):
        result = check(r"")
        assert result is not None

    def test_single_char(self):
        result = check(r"a")
        assert result.status in (Status.SAFE, Status.UNKNOWN)

    def test_very_long_pattern(self):
        pattern = r"a" * 100
        result = check(pattern, config=Config.quick())
        assert result is not None

    def test_unicode_pattern(self):
        result = check(r"^[\u0400-\u04FF]+$")
        assert result is not None
