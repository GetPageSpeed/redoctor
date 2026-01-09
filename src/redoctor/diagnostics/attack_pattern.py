"""Attack pattern representation."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class AttackPattern:
    """Represents an attack string pattern.

    An attack string typically has the structure:
        prefix + (pump * n) + suffix

    Where 'pump' is repeated many times to trigger exponential/polynomial
    backtracking.

    Attributes:
        prefix: The prefix part of the attack string.
        pump: The repeating part (pump string).
        suffix: The suffix part that causes backtracking.
        base: Base repetition count (for complexity calculation).
        repeat: Number of times to repeat the pump.
    """

    prefix: str
    pump: str
    suffix: str
    base: int = 1
    repeat: int = 20

    def build(self, n: Optional[int] = None) -> str:
        """Build the attack string with n repetitions.

        Args:
            n: Number of pump repetitions. Defaults to self.repeat.

        Returns:
            The complete attack string.
        """
        if n is None:
            n = self.repeat
        return self.prefix + (self.pump * n) + self.suffix

    def __str__(self) -> str:
        """Return a human-readable representation."""
        pump_repr = repr(self.pump)
        if len(self.pump) > 20:
            pump_repr = repr(self.pump[:17] + "...")
        return f"{repr(self.prefix)} + {pump_repr} * n + {repr(self.suffix)}"

    def __repr__(self) -> str:
        return f"AttackPattern(prefix={self.prefix!r}, pump={self.pump!r}, suffix={self.suffix!r})"

    @property
    def attack(self) -> str:
        """Return the default attack string."""
        return self.build()

    @classmethod
    def simple(cls, pump: str, suffix: str = "!", repeat: int = 20) -> "AttackPattern":
        """Create a simple attack pattern with no prefix.

        Args:
            pump: The repeating part.
            suffix: The suffix that causes failure.
            repeat: Number of repetitions.
        """
        return cls(prefix="", pump=pump, suffix=suffix, repeat=repeat)

    def with_repeat(self, n: int) -> "AttackPattern":
        """Create a copy with a different repeat count."""
        return AttackPattern(
            prefix=self.prefix,
            pump=self.pump,
            suffix=self.suffix,
            base=self.base,
            repeat=n,
        )
