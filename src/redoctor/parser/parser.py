"""Regex parser for Python dialect."""

from typing import List, Optional, Tuple

from redoctor.parser.ast import (
    Node,
    Pattern,
    Disjunction,
    Sequence,
    Capture,
    NamedCapture,
    NonCapture,
    AtomicGroup,
    FlagsGroup,
    Star,
    Plus,
    Question,
    Quantifier,
    Char,
    Dot,
    CharClass,
    CharClassRange,
    WordChar,
    DigitChar,
    SpaceChar,
    Backref,
    NamedBackref,
    LookAhead,
    NegLookAhead,
    LookBehind,
    NegLookBehind,
    WordBoundary,
    NonWordBoundary,
    LineStart,
    LineEnd,
    StringStart,
    StringEnd,
    Empty,
)
from redoctor.parser.flags import Flags
from redoctor.exceptions import ParseError


class Parser:
    """Regex parser."""

    def __init__(self, source: str, flags: Flags = None):
        self.source = source
        self.pos = 0
        self.flags = flags or Flags()
        self.capture_count = 0
        self.named_captures = {}

    def parse(self) -> Pattern:
        """Parse the entire pattern."""
        node = self._parse_disjunction()
        if self.pos < len(self.source):
            raise ParseError(
                f"Unexpected character: {self.source[self.pos]!r}", self.pos
            )
        return Pattern(node, self.flags, self.source)

    def _current(self) -> str:
        """Get current character or empty string if at end."""
        if self.pos < len(self.source):
            return self.source[self.pos]
        return ""

    def _peek(self, offset: int = 0) -> str:
        """Peek at character at offset from current position."""
        pos = self.pos + offset
        if 0 <= pos < len(self.source):
            return self.source[pos]
        return ""

    def _advance(self) -> str:
        """Advance and return current character."""
        c = self._current()
        self.pos += 1
        return c

    def _expect(self, char: str) -> None:
        """Expect and consume a specific character."""
        if self._current() != char:
            raise ParseError(f"Expected {char!r}, got {self._current()!r}", self.pos)
        self._advance()

    def _match(self, s: str) -> bool:
        """Check if current position matches string s."""
        return self.source[self.pos : self.pos + len(s)] == s

    def _parse_disjunction(self) -> Node:
        """Parse alternation (|)."""
        alternatives = [self._parse_sequence()]

        while self._current() == "|":
            self._advance()
            alternatives.append(self._parse_sequence())

        if len(alternatives) == 1:
            return alternatives[0]
        return Disjunction(alternatives)

    def _parse_sequence(self) -> Node:
        """Parse a sequence of atoms."""
        nodes: List[Node] = []

        while self._current() and self._current() not in "|)":
            node = self._parse_atom()
            if node:
                node = self._parse_quantifier(node)
                nodes.append(node)

        if len(nodes) == 0:
            return Empty()
        if len(nodes) == 1:
            return nodes[0]
        return Sequence(nodes)

    def _parse_atom(self) -> Optional[Node]:
        """Parse a single atom."""
        c = self._current()

        if not c or c in "|)":
            return None

        # Character escapes
        if c == "\\":
            return self._parse_escape()

        # Start of character class
        if c == "[":
            return self._parse_char_class()

        # Grouping
        if c == "(":
            return self._parse_group()

        # Anchors
        if c == "^":
            self._advance()
            return LineStart()

        if c == "$":
            self._advance()
            return LineEnd()

        # Dot
        if c == ".":
            self._advance()
            return Dot(dotall=self.flags.dotall)

        # Literal character
        if c not in "*+?{":
            self._advance()
            return Char(ord(c))

        # Quantifier without atom is an error
        if c in "*+?{":
            raise ParseError("Nothing to repeat", self.pos)

        return None

    def _parse_escape(self) -> Node:
        """Parse an escape sequence."""
        self._expect("\\")
        c = self._current()

        if not c:
            raise ParseError("Trailing backslash", self.pos)

        self._advance()

        # Character class escapes
        if c == "d":
            return DigitChar(negated=False)
        if c == "D":
            return DigitChar(negated=True)
        if c == "w":
            return WordChar(negated=False)
        if c == "W":
            return WordChar(negated=True)
        if c == "s":
            return SpaceChar(negated=False)
        if c == "S":
            return SpaceChar(negated=True)

        # Anchors
        if c == "b":
            return WordBoundary()
        if c == "B":
            return NonWordBoundary()
        if c == "A":
            return StringStart()
        if c == "Z":
            return StringEnd()

        # Backreferences
        if c.isdigit() and c != "0":
            num = c
            while self._current().isdigit():
                num += self._advance()
            return Backref(int(num))

        # Named backreference (?P=name) is handled in _parse_group
        # But \g<name> style
        if c == "g":
            if self._current() == "<":
                self._advance()
                name = ""
                while self._current() and self._current() != ">":
                    name += self._advance()
                if not self._current():
                    raise ParseError("Unterminated group name", self.pos)
                self._expect(">")
                if name.isdigit():
                    return Backref(int(name))
                return NamedBackref(name)

        # Common escapes
        escape_chars = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "f": "\f",
            "v": "\v",
            "0": "\0",
            "a": "\a",
        }
        if c in escape_chars:
            return Char(ord(escape_chars[c]))

        # Hex escapes
        if c == "x":
            hex_chars = ""
            for _ in range(2):
                if self._current() in "0123456789abcdefABCDEF":
                    hex_chars += self._advance()
                else:
                    break
            if len(hex_chars) == 2:
                return Char(int(hex_chars, 16))
            raise ParseError("Invalid hex escape", self.pos)

        # Unicode escapes
        if c == "u":
            hex_chars = ""
            for _ in range(4):
                if self._current() in "0123456789abcdefABCDEF":
                    hex_chars += self._advance()
                else:
                    break
            if len(hex_chars) == 4:
                return Char(int(hex_chars, 16))
            raise ParseError("Invalid unicode escape", self.pos)

        if c == "U":
            hex_chars = ""
            for _ in range(8):
                if self._current() in "0123456789abcdefABCDEF":
                    hex_chars += self._advance()
                else:
                    break
            if len(hex_chars) == 8:
                return Char(int(hex_chars, 16))
            raise ParseError("Invalid unicode escape", self.pos)

        # Literal escape (for special chars)
        if c in r"\.^$*+?{}[]|()":
            return Char(ord(c))

        # Default: literal
        return Char(ord(c))

    def _parse_char_class(self) -> Node:
        """Parse a character class [...]."""
        self._expect("[")
        negated = False
        if self._current() == "^":
            negated = True
            self._advance()

        items: List[Node] = []

        # First character can be literal ]
        if self._current() == "]":
            items.append(Char(ord("]")))
            self._advance()

        while self._current() and self._current() != "]":
            item = self._parse_char_class_item()
            if item:
                # Check for range
                if self._current() == "-" and self._peek(1) not in ("]", ""):
                    if isinstance(item, Char):
                        self._advance()  # consume -
                        end_item = self._parse_char_class_item()
                        if isinstance(end_item, Char):
                            items.append(CharClassRange(item.char, end_item.char))
                        else:
                            items.append(item)
                            items.append(Char(ord("-")))
                            if end_item:
                                items.append(end_item)
                    else:
                        items.append(item)
                else:
                    items.append(item)

        if not self._current():
            raise ParseError("Unterminated character class", self.pos)
        self._expect("]")

        return CharClass(items, negated)

    def _parse_char_class_item(self) -> Optional[Node]:
        """Parse an item inside a character class."""
        c = self._current()
        if not c or c == "]":
            return None

        if c == "\\":
            self._advance()
            c = self._current()
            if not c:
                raise ParseError("Trailing backslash in character class", self.pos)
            self._advance()

            # Character class escapes
            if c == "d":
                return DigitChar(negated=False)
            if c == "D":
                return DigitChar(negated=True)
            if c == "w":
                return WordChar(negated=False)
            if c == "W":
                return WordChar(negated=True)
            if c == "s":
                return SpaceChar(negated=False)
            if c == "S":
                return SpaceChar(negated=True)

            # Common escapes
            escape_chars = {
                "n": "\n",
                "r": "\r",
                "t": "\t",
                "f": "\f",
                "v": "\v",
                "0": "\0",
                "a": "\a",
            }
            if c in escape_chars:
                return Char(ord(escape_chars[c]))

            # Hex escape
            if c == "x":
                hex_chars = ""
                for _ in range(2):
                    if self._current() in "0123456789abcdefABCDEF":
                        hex_chars += self._advance()
                if len(hex_chars) == 2:
                    return Char(int(hex_chars, 16))

            # Literal
            return Char(ord(c))

        self._advance()
        return Char(ord(c))

    def _parse_group(self) -> Node:
        """Parse a group (...)."""
        self._expect("(")

        # Check for special group types
        if self._current() == "?":
            self._advance()
            return self._parse_special_group()

        # Regular capturing group
        self.capture_count += 1
        index = self.capture_count
        child = self._parse_disjunction()
        self._expect(")")
        return Capture(child, index)

    def _parse_special_group(self) -> Node:
        """Parse a special group (?...)."""
        c = self._current()

        # Non-capturing group (?:...)
        if c == ":":
            self._advance()
            child = self._parse_disjunction()
            self._expect(")")
            return NonCapture(child)

        # Lookahead (?=...) and (?!...)
        if c == "=":
            self._advance()
            child = self._parse_disjunction()
            self._expect(")")
            return LookAhead(child)

        if c == "!":
            self._advance()
            child = self._parse_disjunction()
            self._expect(")")
            return NegLookAhead(child)

        # Lookbehind (?<=...) and (?<!...)
        if c == "<":
            self._advance()
            c2 = self._current()
            if c2 == "=":
                self._advance()
                child = self._parse_disjunction()
                self._expect(")")
                return LookBehind(child)
            if c2 == "!":
                self._advance()
                child = self._parse_disjunction()
                self._expect(")")
                return NegLookBehind(child)
            # Named capture (?<name>...) - not Python standard but common
            raise ParseError("Invalid group syntax", self.pos)

        # Named capture (?P<name>...)
        if c == "P":
            self._advance()
            c2 = self._current()
            if c2 == "<":
                self._advance()
                name = ""
                while self._current() and self._current() != ">":
                    name += self._advance()
                if not self._current():
                    raise ParseError("Unterminated group name", self.pos)
                self._expect(">")
                self.capture_count += 1
                index = self.capture_count
                self.named_captures[name] = index
                child = self._parse_disjunction()
                self._expect(")")
                return NamedCapture(child, name, index)
            # Named backreference (?P=name)
            if c2 == "=":
                self._advance()
                name = ""
                while self._current() and self._current() != ")":
                    name += self._advance()
                self._expect(")")
                return NamedBackref(name)

        # Atomic group (?>...)
        if c == ">":
            self._advance()
            child = self._parse_disjunction()
            self._expect(")")
            return AtomicGroup(child)

        # Flags group (?imsx:...) or (?imsx)
        if c in "imsxauL-":
            enable_flags = Flags()
            disable_flags = Flags()
            negating = False

            while self._current() in "imsxauL-":
                fc = self._advance()
                if fc == "-":
                    negating = True
                    continue

                flag_map = {
                    "i": "ignore_case",
                    "m": "multiline",
                    "s": "dotall",
                    "x": "verbose",
                    "a": "ascii",
                    "u": "unicode",
                }
                if fc in flag_map:
                    attr = flag_map[fc]
                    if negating:
                        disable_flags = Flags(**{attr: True})
                    else:
                        enable_flags = Flags(**{attr: True})

            if self._current() == ":":
                self._advance()
                child = self._parse_disjunction()
                self._expect(")")
                return FlagsGroup(child, enable_flags, disable_flags)
            elif self._current() == ")":
                self._advance()
                # Flag-only group modifies global flags
                self.flags = self.flags | enable_flags
                return FlagsGroup(None, enable_flags, disable_flags)

        raise ParseError(f"Unknown group type: (?{c}...)", self.pos)

    def _parse_quantifier(self, node: Node) -> Node:
        """Parse an optional quantifier after an atom."""
        c = self._current()

        if c == "*":
            self._advance()
            greedy, possessive = self._parse_quantifier_suffix()
            return Star(node, greedy=greedy, possessive=possessive)

        if c == "+":
            self._advance()
            greedy, possessive = self._parse_quantifier_suffix()
            return Plus(node, greedy=greedy, possessive=possessive)

        if c == "?":
            self._advance()
            greedy, possessive = self._parse_quantifier_suffix()
            return Question(node, greedy=greedy, possessive=possessive)

        if c == "{":
            return self._parse_bounded_quantifier(node)

        return node

    def _parse_quantifier_suffix(self) -> Tuple[bool, bool]:
        """Parse ? or + after a quantifier for lazy/possessive."""
        c = self._current()
        if c == "?":
            self._advance()
            return False, False  # lazy
        if c == "+":
            self._advance()
            return True, True  # possessive
        return True, False  # greedy

    def _parse_bounded_quantifier(self, node: Node) -> Node:
        """Parse {n}, {n,}, or {n,m} quantifier."""
        self._expect("{")

        # Parse min
        min_str = ""
        while self._current().isdigit():
            min_str += self._advance()

        if not min_str:
            # Not a quantifier, treat { as literal
            self.pos -= 1
            return node

        min_val = int(min_str)
        max_val: Optional[int] = min_val

        if self._current() == ",":
            self._advance()
            max_str = ""
            while self._current().isdigit():
                max_str += self._advance()
            max_val = int(max_str) if max_str else None

        if self._current() != "}":
            # Not a quantifier, backtrack
            raise ParseError("Invalid quantifier", self.pos)
        self._expect("}")

        greedy, possessive = self._parse_quantifier_suffix()
        return Quantifier(
            node, min=min_val, max=max_val, greedy=greedy, possessive=possessive
        )


def parse(pattern: str, flags: Flags = None) -> Pattern:
    """Parse a regex pattern string.

    Args:
        pattern: The regex pattern string.
        flags: Optional flags to use.

    Returns:
        The parsed Pattern AST.

    Raises:
        ParseError: If the pattern is invalid.
    """
    parser = Parser(pattern, flags)
    return parser.parse()
