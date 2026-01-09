"""Character set implemented with intervals."""

from dataclasses import dataclass
from typing import List, Set, Iterator, Optional

from redoctor.unicode.ichar import IChar


@dataclass
class ICharSet:
    """A set of characters partitioned into disjoint intervals.

    This is used for alphabet partitioning in automata construction.

    Attributes:
        chars: List of disjoint IChars.
    """

    chars: List[IChar]

    @classmethod
    def empty(cls) -> "ICharSet":
        """Create an empty character set."""
        return cls([])

    @classmethod
    def from_ichars(cls, ichars: List[IChar]) -> "ICharSet":
        """Create a character set from a list of IChars, partitioning them."""
        if not ichars:
            return cls([])

        # Collect all interval endpoints
        endpoints: Set[int] = set()
        for ic in ichars:
            for start, end in ic.intervals:
                endpoints.add(start)
                endpoints.add(end + 1)

        # Sort endpoints
        sorted_endpoints = sorted(endpoints)

        # Create partitions
        partitions: List[IChar] = []
        for i in range(len(sorted_endpoints) - 1):
            start = sorted_endpoints[i]
            end = sorted_endpoints[i + 1] - 1
            if start <= end:
                partitions.append(IChar(((start, end),)))

        return cls(partitions)

    @classmethod
    def any(cls, dotall: bool = False) -> "ICharSet":
        """Create a character set with any character."""
        return cls([IChar.any(dotall)])

    def __iter__(self) -> Iterator[IChar]:
        """Iterate over characters in the set."""
        return iter(self.chars)

    def __len__(self) -> int:
        """Return the number of partitions."""
        return len(self.chars)

    def __bool__(self) -> bool:
        """Check if the set is non-empty."""
        return len(self.chars) > 0

    def add(self, ichar: IChar) -> "ICharSet":
        """Add an IChar to the set, refining partitions."""
        if not ichar:
            return self

        new_chars = []
        for existing in self.chars:
            intersection = existing.intersect(ichar)
            diff = existing.intersect(ichar.negate())
            if intersection:
                new_chars.append(intersection)
            if diff:
                new_chars.append(diff)

        # Add parts of ichar not covered by existing chars
        covered = IChar(())
        for c in self.chars:
            covered = covered.union(c)
        uncovered = ichar.intersect(covered.negate())
        if uncovered:
            new_chars.append(uncovered)

        return ICharSet(new_chars)

    def union(self, other: "ICharSet") -> "ICharSet":
        """Return the union of two character sets."""
        result = self
        for c in other.chars:
            result = result.add(c)
        return result

    def contains(self, c: int) -> Optional[IChar]:
        """Find which partition contains a character."""
        for ic in self.chars:
            if c in ic:
                return ic
        return None

    def sample_each(self) -> List[int]:
        """Return a sample character from each partition."""
        return [ic.sample() for ic in self.chars if ic.sample() is not None]
