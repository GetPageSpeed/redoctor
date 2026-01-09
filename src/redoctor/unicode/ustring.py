"""Unicode string utilities."""

from dataclasses import dataclass
from typing import Iterator, List, Optional


@dataclass
class UString:
    """A Unicode string with code point iteration.

    Unlike Python strings which iterate over UTF-16 surrogate pairs,
    this iterates over actual code points.

    Attributes:
        chars: List of code points.
    """

    chars: List[int]

    @classmethod
    def from_str(cls, s: str) -> "UString":
        """Create a UString from a Python string."""
        chars = []
        i = 0
        while i < len(s):
            c = ord(s[i])
            # Handle surrogate pairs
            if 0xD800 <= c <= 0xDBFF and i + 1 < len(s):
                c2 = ord(s[i + 1])
                if 0xDC00 <= c2 <= 0xDFFF:
                    c = 0x10000 + ((c - 0xD800) << 10) + (c2 - 0xDC00)
                    i += 1
            chars.append(c)
            i += 1
        return cls(chars)

    @classmethod
    def from_chars(cls, chars: List[int]) -> "UString":
        """Create a UString from a list of code points."""
        return cls(list(chars))

    @classmethod
    def empty(cls) -> "UString":
        """Create an empty UString."""
        return cls([])

    def __str__(self) -> str:
        """Convert to a Python string."""
        return "".join(chr(c) for c in self.chars)

    def __repr__(self) -> str:
        return f"UString({str(self)!r})"

    def __len__(self) -> int:
        """Return the number of code points."""
        return len(self.chars)

    def __iter__(self) -> Iterator[int]:
        """Iterate over code points."""
        return iter(self.chars)

    def __getitem__(self, index: int) -> int:
        """Get code point at index."""
        return self.chars[index]

    def __add__(self, other: "UString") -> "UString":
        """Concatenate two UStrings."""
        return UString(self.chars + other.chars)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UString):
            return self.chars == other.chars
        if isinstance(other, str):
            return str(self) == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(tuple(self.chars))

    def append(self, c: int) -> "UString":
        """Append a code point and return a new UString."""
        return UString(self.chars + [c])

    def repeat(self, n: int) -> "UString":
        """Repeat the string n times."""
        return UString(self.chars * n)

    def slice(self, start: int, end: Optional[int] = None) -> "UString":
        """Return a slice of the string."""
        if end is None:
            return UString(self.chars[start:])
        return UString(self.chars[start:end])

    def is_empty(self) -> bool:
        """Check if the string is empty."""
        return len(self.chars) == 0

    def reverse(self) -> "UString":
        """Return a reversed copy."""
        return UString(self.chars[::-1])
