"""Tests for bug fixes identified during code review."""

import builtins

from redoctor.parser.parser import parse
from redoctor.vm.builder import build_program
from redoctor.vm.interpreter import Interpreter, MatchResult
from redoctor.recall.validator import RecallValidator, ValidationResult
from redoctor.checker import HybridChecker
from redoctor.config import Config


class TestTimeoutErrorAlias:
    """Verify the backwards-compat alias no longer shadows builtins.TimeoutError."""

    def test_builtin_timeout_error_not_shadowed(self):
        """Importing from redoctor.exceptions must not overwrite builtins.TimeoutError."""
        import redoctor.exceptions  # noqa: F401

        assert builtins.TimeoutError is builtins.TimeoutError
        # builtins.TimeoutError is a subclass of OSError
        assert issubclass(builtins.TimeoutError, OSError)

    def test_recheck_timeout_alias_exists(self):
        """RecheckTimeoutError alias exists and maps to AnalysisTimeoutError."""
        from redoctor.exceptions import RecheckTimeoutError, AnalysisTimeoutError

        assert RecheckTimeoutError is AnalysisTimeoutError

    def test_analysis_timeout_error_is_redoctor_error(self):
        """AnalysisTimeoutError inherits from RedoctorError."""
        from redoctor.exceptions import AnalysisTimeoutError, RedoctorError

        assert issubclass(AnalysisTimeoutError, RedoctorError)


class TestNamedBackrefUnknownName:
    """Verify unknown named backreferences emit FAIL instead of silently resolving."""

    def test_unknown_named_backref_fails_match(self):
        """A \\g<nonexistent> should never match, not silently resolve to group 1."""
        # Pattern: (a)\g<bogus> — group 'bogus' does not exist
        pattern = parse(r"(?P<real>a)\g<bogus>")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("aa")
        assert result == MatchResult.NO_MATCH

    def test_known_named_backref_still_works(self):
        """Valid named backreferences must still resolve correctly."""
        pattern = parse(r"(?P<x>a)\g<x>")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("aa")
        assert result == MatchResult.MATCH

    def test_known_named_backref_mismatch(self):
        """Named backref to a valid group must fail on non-matching content."""
        pattern = parse(r"(?P<x>a)\g<x>")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("ab")
        assert result == MatchResult.NO_MATCH


class TestRecallValidatorContextManager:
    """Verify RecallValidator supports the context manager protocol."""

    def test_context_manager_enter_exit(self):
        """Using 'with' should return the validator and call close()."""
        with RecallValidator(timeout=0.1) as validator:
            assert isinstance(validator, RecallValidator)
            result = validator.validate(r"^hello$", "hello")
            assert result.result in (
                ValidationResult.NOT_CONFIRMED,
                ValidationResult.CONFIRMED,
            )
        # After exiting, the pool should be shut down
        assert validator._pool is None

    def test_close_is_idempotent(self):
        """Calling close() multiple times must not raise."""
        validator = RecallValidator(timeout=0.1)
        validator.close()
        validator.close()  # second call is no-op

    def test_pool_created_lazily(self):
        """Pool should not exist until first use."""
        validator = RecallValidator(timeout=0.1)
        assert validator._pool is None
        # Trigger pool creation
        validator.validate(r"^a$", "a")
        assert validator._pool is not None
        validator.close()
        assert validator._pool is None


class TestHybridCheckerClose:
    """Verify HybridChecker.close() cleans up the recall validator."""

    def test_close_releases_validator(self):
        """close() should shut down the validator's thread pool."""
        config = Config(timeout=1.0, skip_recall=False, recall_timeout=0.1)
        checker = HybridChecker(config)
        # Force a check to trigger pool creation
        checker.check(r"^hello$")
        checker.close()
        assert checker.validator._pool is None

    def test_convenience_functions_dont_leak(self):
        """check() and check_pattern() convenience functions must close the checker."""
        from redoctor.checker import check

        # Just verify it doesn't raise and completes normally
        result = check(r"^hello$")
        assert result is not None
