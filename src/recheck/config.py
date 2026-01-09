"""Configuration for recheck analysis."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class CheckerType(Enum):
    """Type of checker to use."""

    AUTO = "auto"
    AUTOMATON = "automaton"
    FUZZ = "fuzz"


class AccelerationMode(Enum):
    """Acceleration mode for VM execution."""

    AUTO = "auto"
    ON = "on"
    OFF = "off"


class SeederType(Enum):
    """Type of seeder for fuzzing."""

    STATIC = "static"
    DYNAMIC = "dynamic"


@dataclass
class Config:
    """Configuration parameters for recheck analysis.

    Attributes:
        checker: Which checker to use (auto, automaton, fuzz).
        timeout: Maximum time in seconds for analysis.
        max_attack_length: Maximum length of generated attack strings.
        attack_limit: Maximum number of attack strings to generate.
        random_seed: Seed for random number generation (for reproducibility).
        acceleration: Acceleration mode for VM execution.
        seeder: Type of seeder for fuzzing.
        max_iterations: Maximum iterations for fuzzing.
        max_nfa_size: Maximum NFA size before falling back to fuzzing.
        max_pattern_size: Maximum pattern size to analyze.
        recall_limit: Maximum number of recall validations.
        recall_timeout: Timeout for each recall validation.
    """

    checker: CheckerType = CheckerType.AUTO
    timeout: float = 10.0
    max_attack_length: int = 4096
    attack_limit: int = 10
    random_seed: Optional[int] = None
    acceleration: AccelerationMode = AccelerationMode.AUTO
    seeder: SeederType = SeederType.STATIC
    max_iterations: int = 100000
    max_nfa_size: int = 35000
    max_pattern_size: int = 1500
    recall_limit: int = 10
    recall_timeout: float = 1.0
    skip_recall: bool = False

    @classmethod
    def default(cls) -> "Config":
        """Create a default configuration."""
        return cls()

    @classmethod
    def quick(cls) -> "Config":
        """Create a quick configuration with shorter timeouts."""
        return cls(
            timeout=1.0,
            max_attack_length=256,
            max_iterations=10000,
            recall_timeout=0.1,
            skip_recall=True,
        )

    @classmethod
    def thorough(cls) -> "Config":
        """Create a thorough configuration with longer timeouts."""
        return cls(
            timeout=30.0,
            max_attack_length=8192,
            max_iterations=500000,
            recall_timeout=5.0,
        )
