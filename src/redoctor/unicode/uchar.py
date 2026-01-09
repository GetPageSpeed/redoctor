"""Unicode code point wrapper."""

from dataclasses import dataclass
from functools import total_ordering
from typing import Union


@total_ordering
@dataclass(frozen=True)
class UChar:
    """A Unicode code point.

    Attributes:
        value: The code point value (0 to 0x10FFFF).
    """

    value: int

    def __post_init__(self):
        if not (0 <= self.value <= 0x10FFFF):
            raise ValueError(f"Invalid code point: {self.value}")

    def __repr__(self) -> str:
        if 0x20 <= self.value <= 0x7E:
            return f"UChar({chr(self.value)!r})"
        return f"UChar(0x{self.value:04X})"

    def __str__(self) -> str:
        return chr(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UChar):
            return self.value == other.value
        if isinstance(other, int):
            return self.value == other
        return NotImplemented

    def __lt__(self, other: "UChar") -> bool:
        if isinstance(other, UChar):
            return self.value < other.value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)

    def __add__(self, other: int) -> "UChar":
        return UChar(self.value + other)

    def __sub__(self, other: "Union[int, UChar]") -> "Union[int, UChar]":
        if isinstance(other, int):
            return UChar(self.value - other)
        return self.value - other.value

    @classmethod
    def from_char(cls, c: str) -> "UChar":
        """Create a UChar from a single character."""
        if len(c) != 1:
            raise ValueError(f"Expected single character, got {len(c)}")
        return cls(ord(c))

    def is_ascii(self) -> bool:
        """Check if this is an ASCII character."""
        return self.value < 128

    def is_bmp(self) -> bool:
        """Check if this is in the Basic Multilingual Plane."""
        return self.value < 0x10000

    def to_lower(self) -> "UChar":
        """Convert to lowercase."""
        return UChar(ord(chr(self.value).lower()))

    def to_upper(self) -> "UChar":
        """Convert to uppercase."""
        return UChar(ord(chr(self.value).upper()))

    def is_word_char(self) -> bool:
        """Check if this is a word character [a-zA-Z0-9_]."""
        c = chr(self.value)
        return c.isalnum() or c == "_"

    def is_digit(self) -> bool:
        """Check if this is a digit [0-9]."""
        return chr(self.value).isdigit()

    def is_space(self) -> bool:
        """Check if this is a whitespace character."""
        return chr(self.value).isspace()


# Common constants
MIN_VALUE = UChar(0)
MAX_VALUE = UChar(0x10FFFF)
MAX_BMP = UChar(0xFFFF)
