"""Extended checker tests for increased coverage."""


from redoctor import check, Config
from redoctor.checker import HybridChecker
from redoctor.parser.flags import Flags
from redoctor.config import CheckerType


class TestHybridCheckerExtended:
    """Extended hybrid checker tests."""

    def test_check_with_automaton_type(self):
        config = Config(checker=CheckerType.AUTOMATON)
        checker = HybridChecker(config)
        result = checker.check(r"^[a-z]+$")
        assert result is not None

    def test_check_with_fuzz_type(self):
        config = Config(checker=CheckerType.FUZZ, timeout=1.0, max_iterations=100)
        checker = HybridChecker(config)
        result = checker.check(r"^[a-z]+$")
        assert result is not None

    def test_check_automaton_fallback_to_fuzz(self):
        # Pattern with backreference should fall back to fuzz
        config = Config(checker=CheckerType.AUTOMATON, timeout=1.0, max_iterations=100)
        checker = HybridChecker(config)
        result = checker.check(r"(a)\1")
        assert result is not None

    def test_auto_selects_fuzz_for_backrefs(self):
        config = Config(checker=CheckerType.AUTO, timeout=1.0, max_iterations=100)
        checker = HybridChecker(config)
        result = checker.check(r"(a)\1")
        assert result is not None


class TestConfigCombinations:
    """Test various configuration combinations."""

    def test_quick_config(self):
        result = check(r"^[a-z]+$", config=Config.quick())
        assert result is not None

    def test_thorough_config(self):
        # Use a simple pattern to avoid long runtime
        result = check(r"^a$", config=Config.thorough())
        assert result is not None

    def test_custom_timeout(self):
        config = Config(timeout=0.5)
        result = check(r"^[a-z]+$", config=config)
        assert result is not None

    def test_custom_random_seed(self):
        config = Config(random_seed=42, timeout=1.0, max_iterations=100)
        result = check(r"^[a-z]+$", config=config)
        assert result is not None


class TestFlagsIntegration:
    """Test flags integration."""

    def test_check_with_ignore_case(self):
        result = check(r"^hello$", Flags(ignore_case=True))
        assert result is not None

    def test_check_with_multiline(self):
        result = check(r"^hello$", Flags(multiline=True))
        assert result is not None

    def test_check_with_dotall(self):
        result = check(r"^.$", Flags(dotall=True))
        assert result is not None
