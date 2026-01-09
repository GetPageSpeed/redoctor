"""Interval-based character representation."""

from dataclasses import dataclass
from typing import Iterator, List, Tuple, Optional, Union

from redoctor.unicode.uchar import UChar


@dataclass(frozen=True)
class IChar:
    """A character represented as a set of code point intervals.

    This is more efficient than storing individual characters for
    character classes like [a-z] or \\w.

    Attributes:
        intervals: List of (start, end) tuples representing inclusive ranges.
    """

    intervals: Tuple[Tuple[int, int], ...]

    def __post_init__(self):
        # Validate intervals
        for start, end in self.intervals:
            if start > end:
                raise ValueError(f"Invalid interval: ({start}, {end})")

    @classmethod
    def from_char(cls, c: "Union[int, str, UChar]") -> "IChar":
        """Create an IChar from a single character."""
        if isinstance(c, str):
            c = ord(c)
        elif isinstance(c, UChar):
            c = c.value
        return cls(((c, c),))

    @classmethod
    def from_range(cls, start: int, end: int) -> "IChar":
        """Create an IChar from a range of characters."""
        return cls(((start, end),))

    @classmethod
    def empty(cls) -> "IChar":
        """Create an empty IChar (matches nothing)."""
        return cls(())

    @classmethod
    def any(cls, dotall: bool = False) -> "IChar":
        """Create an IChar that matches any character.

        Args:
            dotall: If True, includes newlines.
        """
        if dotall:
            return cls(((0, 0x10FFFF),))
        # Exclude newlines
        return cls(((0, 9), (11, 12), (14, 0x10FFFF)))

    @classmethod
    def digit(cls) -> "IChar":
        """Create an IChar for \\d (digits)."""
        return cls(((ord("0"), ord("9")),))

    @classmethod
    def word(cls) -> "IChar":
        """Create an IChar for \\w (word characters)."""
        return cls(
            (
                (ord("0"), ord("9")),
                (ord("A"), ord("Z")),
                (ord("_"), ord("_")),
                (ord("a"), ord("z")),
            )
        )

    @classmethod
    def space(cls) -> "IChar":
        """Create an IChar for \\s (whitespace)."""
        return cls(
            (
                (0x09, 0x0D),  # \\t, \\n, \\v, \\f, \\r
                (0x20, 0x20),  # space
            )
        )

    def __contains__(self, c: "Union[int, str, UChar]") -> bool:
        """Check if a character is in this IChar."""
        if isinstance(c, str):
            c = ord(c)
        elif isinstance(c, UChar):
            c = c.value
        for start, end in self.intervals:
            if start <= c <= end:
                return True
        return False

    def __bool__(self) -> bool:
        """Check if this IChar is non-empty."""
        return len(self.intervals) > 0

    def __repr__(self) -> str:
        if not self.intervals:
            return "IChar()"
        parts = []
        for start, end in self.intervals:
            if start == end:
                c = chr(start) if 0x20 <= start <= 0x7E else f"0x{start:04X}"
                parts.append(c)
            else:
                s = chr(start) if 0x20 <= start <= 0x7E else f"0x{start:04X}"
                e = chr(end) if 0x20 <= end <= 0x7E else f"0x{end:04X}"
                parts.append(f"{s}-{e}")
        return f"IChar([{', '.join(parts)}])"

    def negate(self) -> "IChar":
        """Return the complement of this IChar."""
        if not self.intervals:
            return IChar(((0, 0x10FFFF),))

        result: List[Tuple[int, int]] = []
        prev_end = -1

        for start, end in sorted(self.intervals):
            if prev_end + 1 < start:
                result.append((prev_end + 1, start - 1))
            prev_end = max(prev_end, end)

        if prev_end < 0x10FFFF:
            result.append((prev_end + 1, 0x10FFFF))

        return IChar(tuple(result))

    def union(self, other: "IChar") -> "IChar":
        """Return the union of two IChars."""
        if not self.intervals:
            return other
        if not other.intervals:
            return self

        # Merge all intervals
        all_intervals = sorted(self.intervals + other.intervals)
        result: List[Tuple[int, int]] = []

        for start, end in all_intervals:
            if result and result[-1][1] >= start - 1:
                result[-1] = (result[-1][0], max(result[-1][1], end))
            else:
                result.append((start, end))

        return IChar(tuple(result))

    def intersect(self, other: "IChar") -> "IChar":
        """Return the intersection of two IChars."""
        if not self.intervals or not other.intervals:
            return IChar(())

        result: List[Tuple[int, int]] = []
        i, j = 0, 0

        while i < len(self.intervals) and j < len(other.intervals):
            s1, e1 = self.intervals[i]
            s2, e2 = other.intervals[j]

            # Find overlap
            start = max(s1, s2)
            end = min(e1, e2)

            if start <= end:
                result.append((start, end))

            # Advance the interval that ends first
            if e1 < e2:
                i += 1
            else:
                j += 1

        return IChar(tuple(result))

    def size(self) -> int:
        """Return the number of characters in this IChar."""
        return sum(end - start + 1 for start, end in self.intervals)

    def min(self) -> Optional[int]:
        """Return the minimum character in this IChar."""
        if not self.intervals:
            return None
        return self.intervals[0][0]

    def max(self) -> Optional[int]:
        """Return the maximum character in this IChar."""
        if not self.intervals:
            return None
        return self.intervals[-1][1]

    def sample(self) -> Optional[int]:
        """Return a sample character from this IChar."""
        return self.min()

    def iter_chars(self) -> Iterator[int]:
        """Iterate over all characters in this IChar."""
        for start, end in self.intervals:
            for c in range(start, end + 1):
                yield c

    def to_char_list(self, limit: int = 1000) -> List[int]:
        """Convert to a list of characters (with limit)."""
        result = []
        for c in self.iter_chars():
            result.append(c)
            if len(result) >= limit:
                break
        return result
