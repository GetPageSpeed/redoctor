"""Complexity classification for ReDoS vulnerabilities."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ComplexityType(Enum):
    """Type of time complexity."""

    SAFE = "safe"
    POLYNOMIAL = "polynomial"
    EXPONENTIAL = "exponential"


@dataclass(frozen=True)
class Complexity:
    """Represents the time complexity of a regex match.

    Attributes:
        type: The type of complexity (safe, polynomial, exponential).
        degree: For polynomial complexity, the degree (2 = O(n^2), etc.).
        summary: Human-readable summary.
    """

    type: ComplexityType
    degree: Optional[int] = None
    summary: str = ""

    @classmethod
    def safe(cls) -> "Complexity":
        """Create a safe (linear) complexity."""
        return cls(ComplexityType.SAFE, summary="O(n)")

    @classmethod
    def polynomial(cls, degree: int) -> "Complexity":
        """Create a polynomial complexity.

        Args:
            degree: The polynomial degree (e.g., 2 for O(n^2)).
        """
        return cls(
            ComplexityType.POLYNOMIAL,
            degree=degree,
            summary=f"O(n^{degree})",
        )

    @classmethod
    def exponential(cls) -> "Complexity":
        """Create an exponential complexity."""
        return cls(ComplexityType.EXPONENTIAL, summary="O(2^n)")

    @property
    def is_vulnerable(self) -> bool:
        """Check if this complexity indicates a vulnerability."""
        return self.type in (ComplexityType.POLYNOMIAL, ComplexityType.EXPONENTIAL)

    @property
    def is_safe(self) -> bool:
        """Check if this complexity is safe."""
        return self.type == ComplexityType.SAFE

    @property
    def is_exponential(self) -> bool:
        """Check if this is exponential complexity."""
        return self.type == ComplexityType.EXPONENTIAL

    @property
    def is_polynomial(self) -> bool:
        """Check if this is polynomial complexity."""
        return self.type == ComplexityType.POLYNOMIAL

    def __str__(self) -> str:
        return self.summary

    def __repr__(self) -> str:
        if self.degree is not None:
            return f"Complexity({self.type.value}, degree={self.degree})"
        return f"Complexity({self.type.value})"

    def __lt__(self, other: "Complexity") -> bool:
        """Compare complexities (safe < polynomial < exponential)."""
        type_order = {
            ComplexityType.SAFE: 0,
            ComplexityType.POLYNOMIAL: 1,
            ComplexityType.EXPONENTIAL: 2,
        }
        if type_order[self.type] != type_order[other.type]:
            return type_order[self.type] < type_order[other.type]
        # For polynomials, compare degrees
        if self.type == ComplexityType.POLYNOMIAL:
            return (self.degree or 0) < (other.degree or 0)
        return False

    def worse(self, other: "Complexity") -> "Complexity":
        """Return the worse of two complexities."""
        return max(
            self,
            other,
            key=lambda c: (
                {
                    ComplexityType.SAFE: 0,
                    ComplexityType.POLYNOMIAL: 1,
                    ComplexityType.EXPONENTIAL: 2,
                }[c.type],
                c.degree or 0,
            ),
        )
