"""Regex flags handling."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Flags:
    """Regex flags configuration.

    Attributes:
        ignore_case: Case-insensitive matching (re.IGNORECASE).
        multiline: Multi-line mode (re.MULTILINE).
        dotall: Dot matches newline (re.DOTALL).
        unicode: Unicode matching (re.UNICODE).
        ascii: ASCII-only matching (re.ASCII).
        verbose: Verbose mode (re.VERBOSE).
    """

    ignore_case: bool = False
    multiline: bool = False
    dotall: bool = False
    unicode: bool = True
    ascii: bool = False
    verbose: bool = False

    @classmethod
    def from_re_flags(cls, flags: int) -> "Flags":
        """Create Flags from re module flags."""
        return cls(
            ignore_case=bool(flags & re.IGNORECASE),
            multiline=bool(flags & re.MULTILINE),
            dotall=bool(flags & re.DOTALL),
            unicode=bool(flags & re.UNICODE),
            ascii=bool(flags & re.ASCII),
            verbose=bool(flags & re.VERBOSE),
        )

    def to_re_flags(self) -> int:
        """Convert to re module flags."""
        flags = 0
        if self.ignore_case:
            flags |= re.IGNORECASE
        if self.multiline:
            flags |= re.MULTILINE
        if self.dotall:
            flags |= re.DOTALL
        if self.unicode:
            flags |= re.UNICODE
        if self.ascii:
            flags |= re.ASCII
        if self.verbose:
            flags |= re.VERBOSE
        return flags

    @classmethod
    def from_string(cls, s: str) -> "Flags":
        """Parse flags from string like 'imsx'."""
        return cls(
            ignore_case="i" in s,
            multiline="m" in s,
            dotall="s" in s,
            unicode="u" in s,
            ascii="a" in s,
            verbose="x" in s,
        )

    def __or__(self, other: "Flags") -> "Flags":
        """Merge two flag sets."""
        return Flags(
            ignore_case=self.ignore_case or other.ignore_case,
            multiline=self.multiline or other.multiline,
            dotall=self.dotall or other.dotall,
            unicode=self.unicode or other.unicode,
            ascii=self.ascii or other.ascii,
            verbose=self.verbose or other.verbose,
        )
