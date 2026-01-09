"""Hotspot detection for vulnerable regex portions."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Hotspot:
    """Represents a vulnerable portion of a regex pattern.

    Attributes:
        start: Start position in the pattern.
        end: End position in the pattern (exclusive).
        pattern: The original pattern string.
        temperature: Relative severity (0.0 to 1.0).
    """

    start: int
    end: int
    pattern: str
    temperature: float = 1.0

    @property
    def text(self) -> str:
        """Get the vulnerable portion of the pattern."""
        return self.pattern[self.start : self.end]

    def __str__(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return f"Hotspot({self.start}:{self.end}, {self.text!r})"

    def highlight(self, marker: str = "^") -> str:
        """Return the pattern with the hotspot highlighted.

        Example:
            ^(a+)+$
               ^^^^ <- hotspot

        Returns:
            Multi-line string with pattern and highlight.
        """
        highlight_line = " " * self.start + marker * (self.end - self.start)
        return f"{self.pattern}\n{highlight_line}"

    @classmethod
    def from_positions(cls, positions: List[int], pattern: str) -> "Optional[Hotspot]":
        """Create a hotspot from a list of positions.

        Args:
            positions: List of character positions.
            pattern: The original pattern.

        Returns:
            Hotspot covering the positions, or None if empty.
        """
        if not positions:
            return None
        start = min(positions)
        end = max(positions) + 1
        return cls(start=start, end=end, pattern=pattern)


@dataclass
class HotspotSet:
    """A collection of hotspots in a pattern.

    Attributes:
        hotspots: List of hotspots, sorted by position.
        pattern: The original pattern.
    """

    hotspots: List[Hotspot]
    pattern: str

    @classmethod
    def empty(cls, pattern: str) -> "HotspotSet":
        """Create an empty hotspot set."""
        return cls([], pattern)

    def add(self, hotspot: Hotspot) -> "HotspotSet":
        """Add a hotspot to the set."""
        new_hotspots = sorted(
            self.hotspots + [hotspot],
            key=lambda h: h.start,
        )
        return HotspotSet(new_hotspots, self.pattern)

    @property
    def primary(self) -> "Optional[Hotspot]":
        """Get the primary (hottest) hotspot."""
        if not self.hotspots:
            return None
        return max(self.hotspots, key=lambda h: h.temperature)

    def __iter__(self):
        return iter(self.hotspots)

    def __len__(self) -> int:
        return len(self.hotspots)

    def __bool__(self) -> bool:
        return len(self.hotspots) > 0
