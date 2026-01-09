"""Backtracking interpreter for regex matching."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Tuple

from redoctor.vm.inst import OpCode
from redoctor.vm.program import Program


class MatchResult(Enum):
    """Result of a match attempt."""

    MATCH = auto()  # Successful match
    NO_MATCH = auto()  # No match
    TIMEOUT = auto()  # Step limit exceeded


@dataclass
class Thread:
    """A matching thread (state in the backtracking search).

    Attributes:
        pc: Program counter.
        sp: String position.
        captures: Capture group positions.
        counters: Counter values.
    """

    pc: int
    sp: int
    captures: List[int] = field(default_factory=list)
    counters: List[int] = field(default_factory=list)

    def copy(self) -> "Thread":
        """Create a copy of this thread."""
        return Thread(
            pc=self.pc,
            sp=self.sp,
            captures=list(self.captures),
            counters=list(self.counters),
        )


class Interpreter:
    """Backtracking regex interpreter.

    This implements a simple backtracking interpreter that can
    count steps for complexity analysis.
    """

    def __init__(
        self,
        program: Program,
        max_steps: int = 1000000,
    ):
        self.program = program
        self.max_steps = max_steps
        self.steps = 0

    def match(self, input_str: str) -> Tuple[MatchResult, int]:
        """Try to match the input string.

        Args:
            input_str: The string to match.

        Returns:
            Tuple of (match result, number of steps).
        """
        chars = [ord(c) for c in input_str]
        return self._match_chars(chars)

    def _match_chars(self, chars: List[int]) -> Tuple[MatchResult, int]:
        """Match a list of code points.

        Returns:
            Tuple of (match result, number of steps).
        """
        self.steps = 0

        # Initialize captures
        num_slots = (self.program.num_captures + 1) * 2
        initial_captures = [-1] * num_slots
        initial_counters = [0] * self.program.num_counters

        # Backtracking stack
        stack: List[Thread] = []
        current = Thread(
            pc=0, sp=0, captures=initial_captures, counters=initial_counters
        )

        while True:
            self.steps += 1
            if self.steps > self.max_steps:
                return MatchResult.TIMEOUT, self.steps

            if current.pc >= len(self.program):
                # Ran off the end - try backtracking
                if stack:
                    current = stack.pop()
                    continue
                return MatchResult.NO_MATCH, self.steps

            inst = self.program[current.pc]

            if inst.op == OpCode.MATCH:
                return MatchResult.MATCH, self.steps

            elif inst.op == OpCode.CHAR:
                if (
                    current.sp < len(chars)
                    and inst.char
                    and chars[current.sp] in inst.char
                ):
                    current.sp += 1
                    current.pc += 1
                else:
                    # Backtrack
                    if stack:
                        current = stack.pop()
                    else:
                        return MatchResult.NO_MATCH, self.steps

            elif inst.op == OpCode.ANY:
                if current.sp < len(chars):
                    # Check dotall
                    c = chars[current.sp]
                    if inst.char is None or c in inst.char:
                        current.sp += 1
                        current.pc += 1
                    else:
                        if stack:
                            current = stack.pop()
                        else:
                            return MatchResult.NO_MATCH, self.steps
                else:
                    if stack:
                        current = stack.pop()
                    else:
                        return MatchResult.NO_MATCH, self.steps

            elif inst.op == OpCode.JUMP:
                current.pc = inst.target

            elif inst.op == OpCode.SPLIT:
                # Push second alternative, continue with first
                alt = current.copy()
                alt.pc = inst.target2
                stack.append(alt)
                current.pc = inst.target

            elif inst.op == OpCode.SAVE:
                if inst.slot < len(current.captures):
                    current.captures[inst.slot] = current.sp
                current.pc += 1

            elif inst.op == OpCode.LINE_START:
                if current.sp == 0 or (
                    current.sp > 0 and chars[current.sp - 1] == ord("\n")
                ):
                    current.pc += 1
                else:
                    if stack:
                        current = stack.pop()
                    else:
                        return MatchResult.NO_MATCH, self.steps

            elif inst.op == OpCode.LINE_END:
                if current.sp == len(chars) or (
                    current.sp < len(chars) and chars[current.sp] == ord("\n")
                ):
                    current.pc += 1
                else:
                    if stack:
                        current = stack.pop()
                    else:
                        return MatchResult.NO_MATCH, self.steps

            elif inst.op == OpCode.WORD_BOUNDARY:
                is_boundary = self._is_word_boundary(chars, current.sp)
                if is_boundary:
                    current.pc += 1
                else:
                    if stack:
                        current = stack.pop()
                    else:
                        return MatchResult.NO_MATCH, self.steps

            elif inst.op == OpCode.NON_WORD_BOUNDARY:
                is_boundary = self._is_word_boundary(chars, current.sp)
                if not is_boundary:
                    current.pc += 1
                else:
                    if stack:
                        current = stack.pop()
                    else:
                        return MatchResult.NO_MATCH, self.steps

            elif inst.op == OpCode.BACKREF:
                # Get captured string
                slot = inst.backref * 2
                if slot + 1 < len(current.captures):
                    start = current.captures[slot]
                    end = current.captures[slot + 1]
                    if start >= 0 and end >= 0:
                        ref_chars = chars[start:end]
                        # Try to match
                        if self._match_slice(chars, current.sp, ref_chars):
                            current.sp += len(ref_chars)
                            current.pc += 1
                        else:
                            if stack:
                                current = stack.pop()
                            else:
                                return MatchResult.NO_MATCH, self.steps
                    else:
                        # Backreference not set yet - match empty
                        current.pc += 1
                else:
                    current.pc += 1

            elif inst.op == OpCode.FAIL:
                if stack:
                    current = stack.pop()
                else:
                    return MatchResult.NO_MATCH, self.steps

            elif inst.op in (
                OpCode.LOOKAHEAD_START,
                OpCode.LOOKAHEAD_END,
                OpCode.NEG_LOOKAHEAD_START,
                OpCode.NEG_LOOKAHEAD_END,
                OpCode.LOOKBEHIND_START,
                OpCode.LOOKBEHIND_END,
            ):
                # Simplified: just continue
                current.pc += 1

            elif inst.op == OpCode.COUNTER_RESET:
                if inst.counter < len(current.counters):
                    current.counters[inst.counter] = 0
                current.pc += 1

            elif inst.op == OpCode.COUNTER_INC:
                if inst.counter < len(current.counters):
                    current.counters[inst.counter] += 1
                current.pc += 1

            elif inst.op == OpCode.COUNTER_CHECK:
                if inst.counter < len(current.counters):
                    count = current.counters[inst.counter]
                    max_val = inst.max if inst.max is not None else float("inf")
                    if inst.min <= count <= max_val:
                        current.pc += 1
                    else:
                        if stack:
                            current = stack.pop()
                        else:
                            return MatchResult.NO_MATCH, self.steps
                else:
                    current.pc += 1

            else:
                # Unknown instruction - just continue
                current.pc += 1

    def _is_word_boundary(self, chars: List[int], pos: int) -> bool:
        """Check if position is at a word boundary."""
        before_is_word = False
        after_is_word = False

        if pos > 0:
            before_is_word = self._is_word_char(chars[pos - 1])
        if pos < len(chars):
            after_is_word = self._is_word_char(chars[pos])

        return before_is_word != after_is_word

    def _is_word_char(self, c: int) -> bool:
        """Check if character is a word character."""
        ch = chr(c)
        return ch.isalnum() or ch == "_"

    def _match_slice(self, chars: List[int], pos: int, ref: List[int]) -> bool:
        """Check if chars at pos matches ref."""
        if pos + len(ref) > len(chars):
            return False
        for i, rc in enumerate(ref):
            if chars[pos + i] != rc:
                return False
        return True


def count_steps(program: Program, input_str: str, max_steps: int = 1000000) -> int:
    """Count the number of steps to match a string.

    Args:
        program: The compiled program.
        input_str: The input string.
        max_steps: Maximum steps before timeout.

    Returns:
        Number of steps (or max_steps if timed out).
    """
    interpreter = Interpreter(program, max_steps)
    _, steps = interpreter.match(input_str)
    return steps
