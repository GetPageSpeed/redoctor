"""AST node definitions for regex patterns."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Union

from redoctor.parser.flags import Flags


class Node(ABC):
    """Base class for all AST nodes."""

    @abstractmethod
    def children(self) -> "List[Node]":
        """Return child nodes."""
        ...

    @abstractmethod
    def __repr__(self) -> str:
        ...

    def walk(self):
        """Yield this node and all descendants."""
        yield self
        for child in self.children():
            yield from child.walk()


# ============================================================================
# Top-level pattern
# ============================================================================


@dataclass
class Pattern(Node):
    """Top-level pattern node.

    Attributes:
        node: The root node of the pattern.
        flags: The flags associated with the pattern.
        source: The original source string.
    """

    node: "Node"
    flags: Flags = field(default_factory=Flags)
    source: str = ""

    def children(self) -> "List[Node]":
        return [self.node]

    def __repr__(self) -> str:
        return f"Pattern({self.node!r}, flags={self.flags!r})"


# ============================================================================
# Structural nodes
# ============================================================================


@dataclass
class Disjunction(Node):
    """Alternation (|) between alternatives.

    Attributes:
        alternatives: List of alternative patterns.
    """

    alternatives: "List[Node]"

    def children(self) -> "List[Node]":
        return self.alternatives

    def __repr__(self) -> str:
        return f"Disjunction({self.alternatives!r})"


@dataclass
class Sequence(Node):
    """Sequence of nodes (concatenation).

    Attributes:
        nodes: List of nodes in sequence.
    """

    nodes: "List[Node]"

    def children(self) -> "List[Node]":
        return self.nodes

    def __repr__(self) -> str:
        return f"Sequence({self.nodes!r})"


@dataclass
class Empty(Node):
    """Empty pattern (matches empty string)."""

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "Empty()"


# ============================================================================
# Grouping nodes
# ============================================================================


@dataclass
class Capture(Node):
    """Capturing group.

    Attributes:
        child: The pattern inside the group.
        index: The capture group index (1-based).
    """

    child: "Node"
    index: int = 0

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        return f"Capture({self.child!r}, index={self.index})"


@dataclass
class NamedCapture(Node):
    """Named capturing group (?P<name>...).

    Attributes:
        child: The pattern inside the group.
        name: The name of the capture group.
        index: The capture group index (1-based).
    """

    child: "Node"
    name: str
    index: int = 0

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        return f"NamedCapture({self.child!r}, name={self.name!r}, index={self.index})"


@dataclass
class NonCapture(Node):
    """Non-capturing group (?:...).

    Attributes:
        child: The pattern inside the group.
    """

    child: "Node"

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        return f"NonCapture({self.child!r})"


@dataclass
class AtomicGroup(Node):
    """Atomic group (?>...) - possessive matching.

    Attributes:
        child: The pattern inside the group.
    """

    child: "Node"

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        return f"AtomicGroup({self.child!r})"


@dataclass
class FlagsGroup(Node):
    """Flags modification group (?imsx:...) or (?imsx).

    Attributes:
        child: The pattern inside the group (None for flag-only groups).
        enable: Flags to enable.
        disable: Flags to disable.
    """

    child: "Optional[Node]"
    enable: Flags
    disable: Flags = field(default_factory=Flags)

    def children(self) -> "List[Node]":
        return [self.child] if self.child else []

    def __repr__(self) -> str:
        return f"FlagsGroup({self.child!r}, enable={self.enable!r}, disable={self.disable!r})"


# ============================================================================
# Quantifiers
# ============================================================================


@dataclass
class Repeat(Node):
    """Base class for repetition.

    Attributes:
        child: The pattern to repeat.
        greedy: Whether the quantifier is greedy.
        possessive: Whether the quantifier is possessive.
    """

    child: "Node"
    greedy: bool = True
    possessive: bool = False

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        suffix = ""
        if not self.greedy:
            suffix = ", greedy=False"
        if self.possessive:
            suffix = ", possessive=True"
        return f"{self.__class__.__name__}({self.child!r}{suffix})"


@dataclass
class Star(Repeat):
    """Zero or more repetition (*)."""

    pass


@dataclass
class Plus(Repeat):
    """One or more repetition (+)."""

    pass


@dataclass
class Question(Repeat):
    """Zero or one (?)."""

    pass


@dataclass
class Quantifier(Repeat):
    """Bounded quantifier {n,m}.

    Attributes:
        min: Minimum repetitions.
        max: Maximum repetitions (None for unbounded).
    """

    min: int = 0
    max: Optional[int] = None

    def __repr__(self) -> str:
        suffix = ""
        if not self.greedy:
            suffix = ", greedy=False"
        if self.possessive:
            suffix = ", possessive=True"
        max_str = str(self.max) if self.max is not None else "∞"
        return f"Quantifier({self.child!r}, {{{self.min},{max_str}}}{suffix})"


# ============================================================================
# Character matching
# ============================================================================


@dataclass
class Char(Node):
    """Single character literal.

    Attributes:
        char: The character code point.
    """

    char: int

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        c = chr(self.char)
        if c.isprintable() and c not in "\\\"'":
            return f"Char({c!r})"
        return f"Char(0x{self.char:04x})"

    @classmethod
    def from_str(cls, s: str) -> "Char":
        """Create a Char node from a single-character string."""
        return cls(ord(s))


@dataclass
class Dot(Node):
    """Dot (.) - matches any character.

    Attributes:
        dotall: Whether to match newlines.
    """

    dotall: bool = False

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        if self.dotall:
            return "Dot(dotall=True)"
        return "Dot()"


@dataclass
class CharClassRange(Node):
    """Character range in a character class (e.g., a-z).

    Attributes:
        start: Start character code point.
        end: End character code point.
    """

    start: int
    end: int

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        s = chr(self.start) if chr(self.start).isprintable() else f"0x{self.start:04x}"
        e = chr(self.end) if chr(self.end).isprintable() else f"0x{self.end:04x}"
        return f"CharClassRange({s!r}-{e!r})"


@dataclass
class CharClass(Node):
    """Character class [...].

    Attributes:
        items: List of items (Char, CharClassRange, or nested CharClass).
        negated: Whether the class is negated [^...].
    """

    items: "List[Node]"
    negated: bool = False

    def children(self) -> "List[Node]":
        return self.items

    def __repr__(self) -> str:
        neg = "^" if self.negated else ""
        return f"CharClass([{neg}{self.items!r}])"


# ============================================================================
# Predefined character classes
# ============================================================================


@dataclass
class WordChar(Node):
    """\\w - word character."""

    negated: bool = False

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "WordChar()" if not self.negated else "NonWordChar()"


@dataclass
class DigitChar(Node):
    """\\d - digit character."""

    negated: bool = False

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "DigitChar()" if not self.negated else "NonDigitChar()"


@dataclass
class SpaceChar(Node):
    """\\s - whitespace character."""

    negated: bool = False

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "SpaceChar()" if not self.negated else "NonSpaceChar()"


# ============================================================================
# Assertions
# ============================================================================


@dataclass
class LineStart(Node):
    """^ - start of line (or string in non-multiline mode)."""

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "LineStart()"


@dataclass
class LineEnd(Node):
    """$ - end of line (or string in non-multiline mode)."""

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "LineEnd()"


@dataclass
class StringStart(Node):
    """\\A - start of string."""

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "StringStart()"


@dataclass
class StringEnd(Node):
    """\\Z - end of string."""

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "StringEnd()"


@dataclass
class WordBoundary(Node):
    """\\b - word boundary."""

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "WordBoundary()"


@dataclass
class NonWordBoundary(Node):
    """\\B - non-word boundary."""

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return "NonWordBoundary()"


# ============================================================================
# Lookahead and lookbehind
# ============================================================================


@dataclass
class LookAhead(Node):
    """Positive lookahead (?=...).

    Attributes:
        child: The pattern to match.
    """

    child: "Node"

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        return f"LookAhead({self.child!r})"


@dataclass
class NegLookAhead(Node):
    """Negative lookahead (?!...).

    Attributes:
        child: The pattern that must not match.
    """

    child: "Node"

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        return f"NegLookAhead({self.child!r})"


@dataclass
class LookBehind(Node):
    """Positive lookbehind (?<=...).

    Attributes:
        child: The pattern to match.
    """

    child: "Node"

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        return f"LookBehind({self.child!r})"


@dataclass
class NegLookBehind(Node):
    """Negative lookbehind (?<!...).

    Attributes:
        child: The pattern that must not match.
    """

    child: "Node"

    def children(self) -> "List[Node]":
        return [self.child]

    def __repr__(self) -> str:
        return f"NegLookBehind({self.child!r})"


# ============================================================================
# Backreferences
# ============================================================================


@dataclass
class Backref(Node):
    """Numeric backreference \\1, \\2, etc.

    Attributes:
        index: The capture group index (1-based).
    """

    index: int

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return f"Backref({self.index})"


@dataclass
class NamedBackref(Node):
    """Named backreference (?P=name).

    Attributes:
        name: The name of the capture group.
    """

    name: str

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        return f"NamedBackref({self.name!r})"


# ============================================================================
# Unicode property escapes
# ============================================================================


@dataclass
class UnicodeProperty(Node):
    """Unicode property escape \\p{...} or \\P{...}.

    Attributes:
        name: Property name.
        value: Property value (for binary properties, same as name).
        negated: Whether negated (\\P{...}).
    """

    name: str
    value: str = ""
    negated: bool = False

    def children(self) -> "List[Node]":
        return []

    def __repr__(self) -> str:
        neg = "!" if self.negated else ""
        if self.value:
            return f"UnicodeProperty({neg}{self.name}={self.value})"
        return f"UnicodeProperty({neg}{self.name})"


# ============================================================================
# Conditional patterns
# ============================================================================


@dataclass
class Conditional(Node):
    """Conditional pattern (?(id)yes|no).

    Attributes:
        condition: Group number or name to test.
        yes_branch: Pattern if condition is true.
        no_branch: Pattern if condition is false.
    """

    condition: Union[int, str]
    yes_branch: "Node"
    no_branch: "Optional[Node]" = None

    def children(self) -> "List[Node]":
        if self.no_branch:
            return [self.yes_branch, self.no_branch]
        return [self.yes_branch]

    def __repr__(self) -> str:
        return (
            f"Conditional({self.condition!r}, {self.yes_branch!r}, {self.no_branch!r})"
        )


# ============================================================================
# Helper functions
# ============================================================================


def is_quantifiable(node: Node) -> bool:
    """Check if a node can be quantified."""
    return not isinstance(
        node,
        (
            LineStart,
            LineEnd,
            StringStart,
            StringEnd,
            WordBoundary,
            NonWordBoundary,
            LookAhead,
            NegLookAhead,
            LookBehind,
            NegLookBehind,
            Empty,
        ),
    )


def has_backreferences(node: Node) -> bool:
    """Check if a pattern contains backreferences."""
    for n in node.walk():
        if isinstance(n, (Backref, NamedBackref)):
            return True
    return False


def has_lookaround(node: Node) -> bool:
    """Check if a pattern contains lookahead or lookbehind."""
    for n in node.walk():
        if isinstance(n, (LookAhead, NegLookAhead, LookBehind, NegLookBehind)):
            return True
    return False


def count_captures(node: Node) -> int:
    """Count the number of capturing groups in a pattern."""
    count = 0
    for n in node.walk():
        if isinstance(n, (Capture, NamedCapture)):
            count += 1
    return count
