"""Fuzzing string representation."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class FString:
    """A string used for fuzzing.

    This represents a string with metadata about its structure,
    allowing for intelligent mutation.

    Attributes:
        chars: List of character code points.
        repeat_start: Start of the repeating portion.
        repeat_end: End of the repeating portion.
        repeat_count: Number of times the portion is repeated.
    """

    chars: List[int]
    repeat_start: int = 0
    repeat_end: int = 0
    repeat_count: int = 1

    def __str__(self) -> str:
        return "".join(chr(c) for c in self.chars)

    def __len__(self) -> int:
        return len(self.chars)

    def __repr__(self) -> str:
        return f"FString({str(self)!r})"

    @classmethod
    def from_str(cls, s: str) -> "FString":
        """Create an FString from a Python string."""
        return cls([ord(c) for c in s])

    @classmethod
    def empty(cls) -> "FString":
        """Create an empty FString."""
        return cls([])

    def copy(self) -> "FString":
        """Create a copy of this FString."""
        return FString(
            chars=list(self.chars),
            repeat_start=self.repeat_start,
            repeat_end=self.repeat_end,
            repeat_count=self.repeat_count,
        )

    def with_repeat(self, start: int, end: int, count: int) -> "FString":
        """Create a new FString with repeat metadata."""
        return FString(
            chars=list(self.chars),
            repeat_start=start,
            repeat_end=end,
            repeat_count=count,
        )

    def expand_repeat(self, count: int) -> "FString":
        """Expand the repeating portion to the given count."""
        if self.repeat_start >= self.repeat_end or self.repeat_start < 0:
            return self.copy()

        prefix = self.chars[: self.repeat_start]
        repeat_part = self.chars[self.repeat_start : self.repeat_end]
        suffix = self.chars[self.repeat_end :]

        new_chars = prefix + (repeat_part * count) + suffix
        return FString(
            chars=new_chars,
            repeat_start=self.repeat_start,
            repeat_end=self.repeat_start + len(repeat_part) * count,
            repeat_count=count,
        )

    def insert(self, pos: int, c: int) -> "FString":
        """Insert a character at the given position."""
        new_chars = list(self.chars)
        new_chars.insert(pos, c)
        return FString(chars=new_chars)

    def delete(self, pos: int) -> "FString":
        """Delete the character at the given position."""
        if pos < 0 or pos >= len(self.chars):
            return self.copy()
        new_chars = list(self.chars)
        del new_chars[pos]
        return FString(chars=new_chars)

    def replace(self, pos: int, c: int) -> "FString":
        """Replace the character at the given position."""
        if pos < 0 or pos >= len(self.chars):
            return self.copy()
        new_chars = list(self.chars)
        new_chars[pos] = c
        return FString(chars=new_chars)

    def append(self, c: int) -> "FString":
        """Append a character."""
        return FString(chars=self.chars + [c])

    def extend(self, chars: List[int]) -> "FString":
        """Extend with more characters."""
        return FString(chars=self.chars + chars)

    def concat(self, other: "FString") -> "FString":
        """Concatenate with another FString."""
        return FString(chars=self.chars + other.chars)

    def slice(self, start: int, end: Optional[int] = None) -> "FString":
        """Get a slice of the string."""
        if end is None:
            return FString(chars=self.chars[start:])
        return FString(chars=self.chars[start:end])

    @property
    def prefix(self) -> "FString":
        """Get the prefix (before repeat)."""
        if self.repeat_start > 0:
            return FString(chars=self.chars[: self.repeat_start])
        return FString.empty()

    @property
    def pump(self) -> "FString":
        """Get the pump (repeating portion)."""
        if self.repeat_start < self.repeat_end:
            return FString(chars=self.chars[self.repeat_start : self.repeat_end])
        return FString.empty()

    @property
    def suffix(self) -> "FString":
        """Get the suffix (after repeat)."""
        if self.repeat_end < len(self.chars):
            return FString(chars=self.chars[self.repeat_end :])
        return FString.empty()
