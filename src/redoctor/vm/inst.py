"""VM instruction set for regex matching."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from redoctor.unicode.ichar import IChar


class OpCode(Enum):
    """Instruction opcodes."""

    # Character matching
    CHAR = auto()  # Match a character class
    ANY = auto()  # Match any character (.)

    # Control flow
    JUMP = auto()  # Unconditional jump
    SPLIT = auto()  # Split execution (try both paths)
    MATCH = auto()  # Successfully matched

    # Assertions
    LINE_START = auto()  # ^
    LINE_END = auto()  # $
    WORD_BOUNDARY = auto()  # \b
    NON_WORD_BOUNDARY = auto()  # \B

    # Groups
    SAVE = auto()  # Save position to capture group

    # Counters (for bounded quantifiers)
    COUNTER_RESET = auto()  # Reset counter to 0
    COUNTER_INC = auto()  # Increment counter
    COUNTER_CHECK = auto()  # Check counter against bounds

    # Lookaround
    LOOKAHEAD_START = auto()
    LOOKAHEAD_END = auto()
    NEG_LOOKAHEAD_START = auto()
    NEG_LOOKAHEAD_END = auto()
    LOOKBEHIND_START = auto()
    LOOKBEHIND_END = auto()

    # Backreference
    BACKREF = auto()  # Match backreference

    # Fail
    FAIL = auto()  # Force failure


@dataclass
class Inst:
    """A VM instruction.

    Attributes:
        op: The opcode.
        char: Character class for CHAR instructions.
        target: Jump target for JUMP/SPLIT.
        target2: Second target for SPLIT.
        slot: Capture slot for SAVE.
        counter: Counter index for counter operations.
        min: Minimum count for COUNTER_CHECK.
        max: Maximum count for COUNTER_CHECK.
        backref: Backreference index for BACKREF.
        label: Optional label for debugging.
    """

    op: OpCode
    char: Optional[IChar] = None
    target: int = 0
    target2: int = 0
    slot: int = 0
    counter: int = 0
    min: int = 0
    max: Optional[int] = None
    backref: int = 0
    label: str = ""

    def __repr__(self) -> str:
        parts = [self.op.name]

        if self.op == OpCode.CHAR:
            parts.append(str(self.char))
        elif self.op == OpCode.JUMP:
            parts.append(f"-> {self.target}")
        elif self.op == OpCode.SPLIT:
            parts.append(f"-> {self.target}, {self.target2}")
        elif self.op == OpCode.SAVE:
            parts.append(f"slot={self.slot}")
        elif self.op == OpCode.COUNTER_CHECK:
            max_str = str(self.max) if self.max is not None else "∞"
            parts.append(f"[{self.min}, {max_str}]")
        elif self.op == OpCode.BACKREF:
            parts.append(f"\\{self.backref}")

        if self.label:
            parts.insert(0, f"{self.label}:")

        return " ".join(parts)

    @classmethod
    def char(cls, ichar: IChar, label: str = "") -> "Inst":
        """Create a CHAR instruction."""
        return cls(OpCode.CHAR, char=ichar, label=label)

    @classmethod
    def any_char(cls, dotall: bool = False, label: str = "") -> "Inst":
        """Create an ANY instruction."""
        return cls(OpCode.ANY, char=IChar.any(dotall), label=label)

    @classmethod
    def jump(cls, target: int, label: str = "") -> "Inst":
        """Create a JUMP instruction."""
        return cls(OpCode.JUMP, target=target, label=label)

    @classmethod
    def split(cls, target1: int, target2: int, label: str = "") -> "Inst":
        """Create a SPLIT instruction."""
        return cls(OpCode.SPLIT, target=target1, target2=target2, label=label)

    @classmethod
    def match(cls, label: str = "") -> "Inst":
        """Create a MATCH instruction."""
        return cls(OpCode.MATCH, label=label)

    @classmethod
    def save(cls, slot: int, label: str = "") -> "Inst":
        """Create a SAVE instruction."""
        return cls(OpCode.SAVE, slot=slot, label=label)

    @classmethod
    def line_start(cls, label: str = "") -> "Inst":
        """Create a LINE_START instruction."""
        return cls(OpCode.LINE_START, label=label)

    @classmethod
    def line_end(cls, label: str = "") -> "Inst":
        """Create a LINE_END instruction."""
        return cls(OpCode.LINE_END, label=label)

    @classmethod
    def word_boundary(cls, label: str = "") -> "Inst":
        """Create a WORD_BOUNDARY instruction."""
        return cls(OpCode.WORD_BOUNDARY, label=label)

    @classmethod
    def backref(cls, index: int, label: str = "") -> "Inst":
        """Create a BACKREF instruction."""
        return cls(OpCode.BACKREF, backref=index, label=label)

    @classmethod
    def fail(cls, label: str = "") -> "Inst":
        """Create a FAIL instruction."""
        return cls(OpCode.FAIL, label=label)
