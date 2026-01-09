"""Tests for recall validation."""


from redoctor.recall.validator import RecallValidator, ValidationResult, validate_attack


class TestRecallValidator:
    """Test recall validation."""

    def test_validate_safe_pattern(self):
        validator = RecallValidator(timeout=0.5)
        result = validator.validate(r"^[a-z]+$", "hello")
        assert result.result in (
            ValidationResult.NOT_CONFIRMED,
            ValidationResult.CONFIRMED,
        )
        assert result.execution_time >= 0

    def test_validate_invalid_regex(self):
        validator = RecallValidator()
        result = validator.validate(r"(unclosed", "test")
        assert result.result == ValidationResult.ERROR
        assert result.error is not None

    def test_validate_with_scaling(self):
        validator = RecallValidator(timeout=0.5)
        result = validator.validate_with_scaling(
            pattern=r"^[a-z]+$",
            prefix="",
            pump="a",
            suffix="!",
            max_pump_count=10,
        )
        assert result.result in (
            ValidationResult.NOT_CONFIRMED,
            ValidationResult.CONFIRMED,
            ValidationResult.TIMEOUT,
        )

    def test_validate_attack_function(self):
        # Should not detect simple pattern as vulnerable
        result = validate_attack(r"^hello$", "hello", timeout=0.1)
        assert result is False  # Simple pattern should not be vulnerable


class TestValidationResult:
    """Test validation result enum."""

    def test_result_values(self):
        assert ValidationResult.CONFIRMED.name == "CONFIRMED"
        assert ValidationResult.NOT_CONFIRMED.name == "NOT_CONFIRMED"
        assert ValidationResult.TIMEOUT.name == "TIMEOUT"
        assert ValidationResult.ERROR.name == "ERROR"
