"""Runtime validation using isolated regex execution."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Tuple
import json
import subprocess  # nosec B404 - required for the isolated recall worker
import sys


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


class RecallValidator:
    """Validates ReDoS vulnerabilities using actual regex execution.

    This confirms detected vulnerabilities by measuring actual execution
    time with Python's re module.

    Supports the context manager protocol for deterministic cleanup::

        with RecallValidator(timeout=1.0) as validator:
            result = validator.validate(pattern, attack)
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

    def __enter__(self) -> "RecallValidator":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

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
        baseline_time, error = self._measure_match_time(pattern, "a", flags)
        if error:
            return RecallResult(
                result=ValidationResult.ERROR,
                error=error,
            )

        # Measure attack string
        attack_time, error = self._measure_match_time(pattern, attack_string, flags)
        if error:
            return RecallResult(result=ValidationResult.ERROR, error=error)

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
        # Measure execution times for increasing pump counts
        times = []
        for n in [5, 10, 15, 20, 25]:
            if n > max_pump_count:
                break

            attack = prefix + pump * n + suffix
            exec_time, error = self._measure_match_time(pattern, attack, flags)

            if error:
                return RecallResult(result=ValidationResult.ERROR, error=error)

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

    def close(self) -> None:
        """Retain the context-manager API; workers are one-shot processes."""

    def _measure_match_time(
        self,
        pattern: str,
        string: str,
        flags: int = 0,
    ) -> Tuple[Optional[float], Optional[str]]:
        """Measure a match in a killable child interpreter.

        Python's regex engine can retain the GIL during catastrophic
        backtracking, so a thread timeout cannot protect the caller. A fresh
        interpreter process gives the timeout a hard termination boundary.

        Returns:
            A pair of execution time and error. A timed-out match is
            ``(None, None)``.
        """
        try:
            # The command is fixed, shell-free, and regex data travels only on
            # stdin. This process boundary is what makes the timeout killable.
            completed = subprocess.run(  # nosec B603
                [sys.executable, "-m", "redoctor.recall.worker"],
                input=json.dumps(
                    {"pattern": pattern, "string": string, "flags": flags}
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None, None
        except (OSError, ValueError) as error:
            return None, f"Recall worker failed: {error}"

        if completed.returncode != 0:
            return None, "Recall worker exited unexpectedly."

        try:
            result = json.loads(completed.stdout)
        except (TypeError, ValueError):
            return None, "Recall worker returned invalid output."

        if result.get("error"):
            return None, result["error"]
        return result.get("elapsed"), None


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
