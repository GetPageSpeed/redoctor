"""Full diagnostic result."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from redoctor.diagnostics.complexity import Complexity
from redoctor.diagnostics.attack_pattern import AttackPattern
from redoctor.diagnostics.hotspot import Hotspot


class Status(Enum):
    """Status of the analysis."""

    SAFE = "safe"
    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class Diagnostics:
    """Complete diagnostic result from recheck analysis.

    Attributes:
        status: The overall status (safe, vulnerable, unknown, error).
        source: The original regex pattern.
        flags: The regex flags used.
        complexity: The detected complexity.
        attack_pattern: The attack pattern if vulnerable.
        hotspot: The vulnerable portion of the regex.
        checker: Which checker produced this result.
        message: Human-readable message.
        error: Error message if status is ERROR.
    """

    status: Status
    source: str
    flags: str = ""
    complexity: Optional[Complexity] = None
    attack_pattern: Optional[AttackPattern] = None
    hotspot: Optional[Hotspot] = None
    checker: str = ""
    message: str = ""
    error: Optional[str] = None

    @classmethod
    def safe(cls, source: str, flags: str = "", checker: str = "") -> "Diagnostics":
        """Create a safe diagnostic result."""
        return cls(
            status=Status.SAFE,
            source=source,
            flags=flags,
            complexity=Complexity.safe(),
            checker=checker,
            message="No ReDoS vulnerability detected.",
        )

    @classmethod
    def vulnerable(
        cls,
        source: str,
        complexity: Complexity,
        attack_pattern: AttackPattern,
        hotspot: Optional[Hotspot] = None,
        flags: str = "",
        checker: str = "",
    ) -> "Diagnostics":
        """Create a vulnerable diagnostic result."""
        return cls(
            status=Status.VULNERABLE,
            source=source,
            flags=flags,
            complexity=complexity,
            attack_pattern=attack_pattern,
            hotspot=hotspot,
            checker=checker,
            message=f"ReDoS vulnerability detected with {complexity} complexity.",
        )

    @classmethod
    def unknown(
        cls, source: str, flags: str = "", checker: str = "", message: str = ""
    ) -> "Diagnostics":
        """Create an unknown diagnostic result."""
        return cls(
            status=Status.UNKNOWN,
            source=source,
            flags=flags,
            checker=checker,
            message=message or "Unable to determine vulnerability status.",
        )

    @classmethod
    def from_error(cls, source: str, error: str, flags: str = "") -> "Diagnostics":
        """Create an error diagnostic result."""
        return cls(
            status=Status.ERROR,
            source=source,
            flags=flags,
            error=error,
            message=f"Error during analysis: {error}",
        )

    @property
    def is_vulnerable(self) -> bool:
        """Check if the regex is vulnerable."""
        return self.status == Status.VULNERABLE

    @property
    def is_safe(self) -> bool:
        """Check if the regex is safe."""
        return self.status == Status.SAFE

    @property
    def attack(self) -> Optional[str]:
        """Get the attack string if vulnerable."""
        if self.attack_pattern:
            return self.attack_pattern.attack
        return None

    def __str__(self) -> str:
        lines = [f"Pattern: {self.source}"]
        lines.append(f"Status: {self.status.value}")

        if self.complexity:
            lines.append(f"Complexity: {self.complexity}")

        if self.attack_pattern:
            lines.append(f"Attack: {self.attack_pattern}")

        if self.hotspot:
            lines.append(f"Hotspot: {self.hotspot}")

        if self.message:
            lines.append(f"Message: {self.message}")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Convert to a dictionary for JSON serialization."""
        result = {
            "status": self.status.value,
            "source": self.source,
            "flags": self.flags,
            "message": self.message,
        }

        if self.complexity:
            result["complexity"] = {
                "type": self.complexity.type.value,
                "degree": self.complexity.degree,
                "summary": self.complexity.summary,
            }

        if self.attack_pattern:
            result["attack"] = {
                "pattern": str(self.attack_pattern),
                "string": self.attack_pattern.attack,
                "prefix": self.attack_pattern.prefix,
                "pump": self.attack_pattern.pump,
                "suffix": self.attack_pattern.suffix,
            }

        if self.hotspot:
            result["hotspot"] = {
                "start": self.hotspot.start,
                "end": self.hotspot.end,
                "text": self.hotspot.text,
            }

        if self.error:
            result["error"] = self.error

        if self.checker:
            result["checker"] = self.checker

        return result
