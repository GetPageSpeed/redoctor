"""Extended recall tests for increased coverage."""


from redoctor.recall.validator import RecallValidator, ValidationResult, RecallResult


class TestRecallValidatorExtended:
    """Extended recall validator tests."""

    def test_validate_with_flags(self):
        import re

        validator = RecallValidator(timeout=0.1)
        result = validator.validate(r"^hello$", "HELLO", flags=re.IGNORECASE)
        assert result.result in (
            ValidationResult.NOT_CONFIRMED,
            ValidationResult.CONFIRMED,
        )

    def test_validate_timeout(self):
        # Use a pattern and input that might be slow
        validator = RecallValidator(timeout=0.001)
        result = validator.validate(r"^[a-z]+$", "a" * 1000)
        # Should complete without hanging
        assert result.result in (
            ValidationResult.NOT_CONFIRMED,
            ValidationResult.CONFIRMED,
            ValidationResult.TIMEOUT,
        )

    def test_validate_empty_pattern(self):
        validator = RecallValidator()
        result = validator.validate(r"", "test")
        assert result.result in (
            ValidationResult.NOT_CONFIRMED,
            ValidationResult.CONFIRMED,
        )

    def test_validate_empty_string(self):
        validator = RecallValidator()
        result = validator.validate(r".*", "")
        assert result.result in (
            ValidationResult.NOT_CONFIRMED,
            ValidationResult.CONFIRMED,
        )


class TestRecallResult:
    """Test RecallResult dataclass."""

    def test_result_attributes(self):
        result = RecallResult(
            result=ValidationResult.CONFIRMED,
            execution_time=0.5,
            attack_string="test",
            error=None,
        )
        assert result.result == ValidationResult.CONFIRMED
        assert result.execution_time == 0.5
        assert result.attack_string == "test"
        assert result.error is None

    def test_result_with_error(self):
        result = RecallResult(
            result=ValidationResult.ERROR,
            error="Something went wrong",
        )
        assert result.error == "Something went wrong"
