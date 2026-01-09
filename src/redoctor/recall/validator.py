"""Runtime validation using actual regex execution."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Pattern
import re
import time


class ValidationResult(Enum):
    """Result of validation."""

    CONFIRMED = auto()  # Vulnerability confirmed
    NOT_CONFIRMED = auto()  # Could not confirm vulnerability
    TIMEOUT = auto()  # Validation timed out
    ERROR = auto()  # Error during validation


@dataclass
class RecallResult:
    """Detailed result of recall validation.

    Attributes:
        result: The validation result.
        execution_time: Time taken for the match attempt.
        attack_string: The string that triggered the vulnerability.
        error: Error message if any.
    """

    result: ValidationResult
    execution_time: float = 0.0
    attack_string: str = ""
    error: Optional[str] = None


class TimeoutException(Exception):
    """Raised when validation times out."""

    pass


def _timeout_handler(signum, frame):
    raise TimeoutException("Validation timed out")


class RecallValidator:
    """Validates ReDoS vulnerabilities using actual regex execution.

    This confirms detected vulnerabilities by measuring actual execution
    time with Python's re module.
    """

    def __init__(
        self,
        timeout: float = 1.0,
        threshold_ratio: float = 10.0,
    ):
        """Initialize the validator.

        Args:
            timeout: Maximum time in seconds for each match attempt.
            threshold_ratio: Ratio of time increase to confirm vulnerability.
        """
        self.timeout = timeout
        self.threshold_ratio = threshold_ratio

    def validate(
        self,
        pattern: str,
        attack_string: str,
        flags: int = 0,
    ) -> RecallResult:
        """Validate a potential vulnerability.

        Args:
            pattern: The regex pattern.
            attack_string: The attack string to test.
            flags: Python re module flags.

        Returns:
            RecallResult with validation outcome.
        """
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            return RecallResult(
                result=ValidationResult.ERROR,
                error=f"Invalid regex: {e}",
            )

        # Measure baseline with a short string
        baseline_time = self._measure_match_time(regex, "a")

        # Measure attack string
        attack_time = self._measure_match_time(regex, attack_string)

        if attack_time is None:
            return RecallResult(
                result=ValidationResult.TIMEOUT,
                execution_time=self.timeout,
                attack_string=attack_string,
            )

        # Check if attack time significantly exceeds baseline
        if baseline_time is not None and baseline_time > 0:
            ratio = attack_time / baseline_time
            if ratio > self.threshold_ratio:
                return RecallResult(
                    result=ValidationResult.CONFIRMED,
                    execution_time=attack_time,
                    attack_string=attack_string,
                )

        # Also check absolute time
        if attack_time > 0.1:  # More than 100ms is suspicious
            return RecallResult(
                result=ValidationResult.CONFIRMED,
                execution_time=attack_time,
                attack_string=attack_string,
            )

        return RecallResult(
            result=ValidationResult.NOT_CONFIRMED,
            execution_time=attack_time,
            attack_string=attack_string,
        )

    def validate_with_scaling(
        self,
        pattern: str,
        prefix: str,
        pump: str,
        suffix: str,
        flags: int = 0,
        max_pump_count: int = 50,
    ) -> RecallResult:
        """Validate by testing increasing pump counts.

        This is more reliable as it checks for superlinear time growth.

        Args:
            pattern: The regex pattern.
            prefix: Attack string prefix.
            pump: The pump string.
            suffix: Attack string suffix.
            flags: Python re module flags.
            max_pump_count: Maximum pump repetitions to test.

        Returns:
            RecallResult with validation outcome.
        """
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            return RecallResult(
                result=ValidationResult.ERROR,
                error=f"Invalid regex: {e}",
            )

        # Measure execution times for increasing pump counts
        times = []
        for n in [5, 10, 15, 20, 25]:
            if n > max_pump_count:
                break

            attack = prefix + pump * n + suffix
            exec_time = self._measure_match_time(regex, attack)

            if exec_time is None:
                # Timed out - definitely vulnerable
                return RecallResult(
                    result=ValidationResult.CONFIRMED,
                    execution_time=self.timeout,
                    attack_string=attack,
                )

            times.append((n, exec_time))

        # Analyze time growth
        if len(times) >= 2:
            n1, t1 = times[0]
            n2, t2 = times[-1]

            if t1 > 0:
                time_ratio = t2 / t1
                n_ratio = n2 / n1

                # Exponential: time ratio >> n_ratio
                # Polynomial: time ratio > n_ratio^1.5
                # Linear: time ratio ≈ n_ratio

                if time_ratio > n_ratio**2:
                    return RecallResult(
                        result=ValidationResult.CONFIRMED,
                        execution_time=t2,
                        attack_string=prefix + pump * n2 + suffix,
                    )

        return RecallResult(
            result=ValidationResult.NOT_CONFIRMED,
            execution_time=times[-1][1] if times else 0.0,
            attack_string=prefix + pump * max_pump_count + suffix,
        )

    def _measure_match_time(
        self,
        regex: Pattern,
        string: str,
    ) -> Optional[float]:
        """Measure time to match a string.

        Returns:
            Execution time in seconds, or None if timed out.
        """
        # Use simple timing (signal-based timeout not available on all platforms)
        start = time.perf_counter()

        try:
            # Try matching
            regex.match(string)

            end = time.perf_counter()
            elapsed = end - start

            # Check if we exceeded timeout
            if elapsed > self.timeout:
                return None
            return elapsed

        except Exception:
            return None


def validate_attack(
    pattern: str,
    attack_string: str,
    timeout: float = 1.0,
) -> bool:
    """Quick validation of an attack string.

    Args:
        pattern: The regex pattern.
        attack_string: The attack string.
        timeout: Timeout in seconds.

    Returns:
        True if vulnerability is confirmed.
    """
    validator = RecallValidator(timeout=timeout)
    result = validator.validate(pattern, attack_string)
    return result.result == ValidationResult.CONFIRMED
