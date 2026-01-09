"""Build VM program from regex AST."""


from redoctor.parser.ast import (
    Node,
    Pattern,
    Disjunction,
    Sequence,
    Empty,
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
    Backref,
    NamedBackref,
)
from redoctor.parser.flags import Flags
from redoctor.vm.inst import Inst, OpCode
from redoctor.vm.program import Program
from redoctor.unicode.ichar import IChar


class ProgramBuilder:
    """Builds a VM program from a regex AST."""

    def __init__(self, flags: Flags = None):
        self.program = Program()
        self.flags = flags or Flags()
        self.capture_count = 0

    def build(self, pattern: Pattern) -> Program:
        """Build a program from a pattern."""
        self.flags = pattern.flags

        # Compile the pattern
        self._compile(pattern.node)

        # Add match instruction
        self.program.add(Inst.match())

        self.program.num_captures = self.capture_count
        return self.program

    def _emit(self, inst: Inst) -> int:
        """Emit an instruction and return its index."""
        return self.program.add(inst)

    def _compile(self, node: Node) -> None:
        """Compile a node."""
        if isinstance(node, Empty):
            pass  # Nothing to emit

        elif isinstance(node, Char):
            self._compile_char(node)

        elif isinstance(node, Dot):
            self._compile_dot(node)

        elif isinstance(node, CharClass):
            self._compile_char_class(node)

        elif isinstance(node, (WordChar, DigitChar, SpaceChar)):
            self._compile_predefined_class(node)

        elif isinstance(node, Disjunction):
            self._compile_disjunction(node)

        elif isinstance(node, Sequence):
            self._compile_sequence(node)

        elif isinstance(node, Capture):
            self._compile_capture(node)

        elif isinstance(node, NamedCapture):
            self._compile_named_capture(node)

        elif isinstance(node, NonCapture):
            self._compile(node.child)

        elif isinstance(node, FlagsGroup):
            if node.child:
                self._compile(node.child)

        elif isinstance(node, AtomicGroup):
            # Atomic groups are compiled as regular groups
            self._compile(node.child)

        elif isinstance(node, Star):
            self._compile_star(node)

        elif isinstance(node, Plus):
            self._compile_plus(node)

        elif isinstance(node, Question):
            self._compile_question(node)

        elif isinstance(node, Quantifier):
            self._compile_quantifier(node)

        elif isinstance(node, LineStart):
            self._emit(Inst.line_start())

        elif isinstance(node, LineEnd):
            self._emit(Inst.line_end())

        elif isinstance(node, WordBoundary):
            self._emit(Inst.word_boundary())

        elif isinstance(node, NonWordBoundary):
            self._emit(Inst(OpCode.NON_WORD_BOUNDARY))

        elif isinstance(node, (StringStart, StringEnd)):
            # String anchors are similar to line anchors
            if isinstance(node, StringStart):
                self._emit(Inst.line_start())
            else:
                self._emit(Inst.line_end())

        elif isinstance(node, Backref):
            self._emit(Inst.backref(node.index))

        elif isinstance(node, NamedBackref):
            # Named backrefs need name resolution
            self._emit(Inst.backref(1))  # Placeholder

        elif isinstance(node, (LookAhead, NegLookAhead, LookBehind, NegLookBehind)):
            self._compile_lookaround(node)

    def _compile_char(self, node: Char) -> None:
        """Compile a single character."""
        char = IChar.from_char(node.char)
        if self.flags.ignore_case:
            c = chr(node.char)
            lower = c.lower()
            upper = c.upper()
            chars = {node.char}
            if lower != c:
                chars.add(ord(lower))
            if upper != c:
                chars.add(ord(upper))
            intervals = tuple((c, c) for c in sorted(chars))
            char = IChar(intervals)
        self._emit(Inst.char(char))

    def _compile_dot(self, node: Dot) -> None:
        """Compile dot (any character)."""
        self._emit(Inst.any_char(dotall=node.dotall or self.flags.dotall))

    def _compile_char_class(self, node: CharClass) -> None:
        """Compile a character class."""
        char = self._compute_char_class(node)
        if node.negated:
            char = char.negate()
        self._emit(Inst.char(char))

    def _compute_char_class(self, node: CharClass) -> IChar:
        """Compute the IChar for a character class."""
        result = IChar.empty()
        for item in node.items:
            if isinstance(item, Char):
                result = result.union(IChar.from_char(item.char))
            elif isinstance(item, CharClassRange):
                result = result.union(IChar.from_range(item.start, item.end))
            elif isinstance(item, WordChar):
                ic = IChar.word()
                if item.negated:
                    ic = ic.negate()
                result = result.union(ic)
            elif isinstance(item, DigitChar):
                ic = IChar.digit()
                if item.negated:
                    ic = ic.negate()
                result = result.union(ic)
            elif isinstance(item, SpaceChar):
                ic = IChar.space()
                if item.negated:
                    ic = ic.negate()
                result = result.union(ic)
        return result

    def _compile_predefined_class(self, node: Node) -> None:
        """Compile predefined character classes."""
        if isinstance(node, WordChar):
            char = IChar.word()
            if node.negated:
                char = char.negate()
        elif isinstance(node, DigitChar):
            char = IChar.digit()
            if node.negated:
                char = char.negate()
        elif isinstance(node, SpaceChar):
            char = IChar.space()
            if node.negated:
                char = char.negate()
        else:
            char = IChar.any()
        self._emit(Inst.char(char))

    def _compile_disjunction(self, node: Disjunction) -> None:
        """Compile alternation."""
        if len(node.alternatives) == 0:
            return
        if len(node.alternatives) == 1:
            self._compile(node.alternatives[0])
            return

        # Chain of splits: split(alt0, split(alt1, split(alt2, ...)))
        jumps = []
        for i, alt in enumerate(node.alternatives):
            if i < len(node.alternatives) - 1:
                split_idx = self._emit(Inst.split(0, 0))
                self._compile(alt)
                jump_idx = self._emit(Inst.jump(0))
                jumps.append(jump_idx)
                self.program.patch(split_idx, split_idx + 1)
                self.program.patch2(split_idx, len(self.program))
            else:
                self._compile(alt)

        # Patch all jumps to end
        end = len(self.program)
        for jump_idx in jumps:
            self.program.patch(jump_idx, end)

    def _compile_sequence(self, node: Sequence) -> None:
        """Compile a sequence."""
        for child in node.nodes:
            self._compile(child)

    def _compile_capture(self, node: Capture) -> None:
        """Compile a capture group."""
        slot = node.index * 2
        self._emit(Inst.save(slot))
        self._compile(node.child)
        self._emit(Inst.save(slot + 1))
        self.capture_count = max(self.capture_count, node.index)

    def _compile_named_capture(self, node: NamedCapture) -> None:
        """Compile a named capture group."""
        slot = node.index * 2
        self._emit(Inst.save(slot))
        self._compile(node.child)
        self._emit(Inst.save(slot + 1))
        self.capture_count = max(self.capture_count, node.index)

    def _compile_star(self, node: Star) -> None:
        """Compile * (zero or more)."""
        loop_start = len(self.program)

        if node.greedy:
            split_idx = self._emit(Inst.split(0, 0))
            self._compile(node.child)
            self._emit(Inst.jump(loop_start))
            self.program.patch(split_idx, loop_start + 1)
            self.program.patch2(split_idx, len(self.program))
        else:
            split_idx = self._emit(Inst.split(0, 0))
            self.program.patch2(split_idx, loop_start + 1)
            self._compile(node.child)
            self._emit(Inst.jump(loop_start))
            self.program.patch(split_idx, len(self.program))

    def _compile_plus(self, node: Plus) -> None:
        """Compile + (one or more)."""
        loop_start = len(self.program)
        self._compile(node.child)

        if node.greedy:
            split_idx = self._emit(Inst.split(loop_start, 0))
            self.program.patch2(split_idx, len(self.program))
        else:
            split_idx = self._emit(Inst.split(0, loop_start))
            self.program.patch(split_idx, len(self.program))

    def _compile_question(self, node: Question) -> None:
        """Compile ? (zero or one)."""
        if node.greedy:
            # Greedy: try body first, then skip
            split_idx = self._emit(Inst.split(0, 0))
            self._compile(node.child)
            self.program.patch(split_idx, split_idx + 1)  # target1 = body
            self.program.patch2(split_idx, len(self.program))  # target2 = after body
        else:
            # Lazy: try to skip first, then try body
            split_idx = self._emit(Inst.split(0, 0))
            body_start = len(self.program)
            self._compile(node.child)
            end = len(self.program)
            self.program.patch(split_idx, end)  # target1 = skip body (go to end)
            self.program.patch2(split_idx, body_start)  # target2 = try body

    def _compile_quantifier(self, node: Quantifier) -> None:
        """Compile {n,m} quantifier."""
        # Emit min required copies
        for _ in range(node.min):
            self._compile(node.child)

        if node.max is None:
            # Unbounded: add * at the end
            loop_start = len(self.program)
            if node.greedy:
                split_idx = self._emit(Inst.split(0, 0))
                self._compile(node.child)
                self._emit(Inst.jump(loop_start))
                self.program.patch(split_idx, loop_start + 1)
                self.program.patch2(split_idx, len(self.program))
            else:
                split_idx = self._emit(Inst.split(0, 0))
                self.program.patch2(split_idx, loop_start + 1)
                self._compile(node.child)
                self._emit(Inst.jump(loop_start))
                self.program.patch(split_idx, len(self.program))
        else:
            # Bounded: add optional copies
            for _ in range(node.min, node.max):
                if node.greedy:
                    # Greedy: try body first, then skip
                    split_idx = self._emit(Inst.split(0, 0))
                    self._compile(node.child)
                    self.program.patch(split_idx, split_idx + 1)  # target1 = body
                    self.program.patch2(split_idx, len(self.program))  # target2 = skip
                else:
                    # Lazy: try to skip first, then try body
                    split_idx = self._emit(Inst.split(0, 0))
                    body_start = len(self.program)
                    self._compile(node.child)
                    self.program.patch(split_idx, len(self.program))  # target1 = skip
                    self.program.patch2(split_idx, body_start)  # target2 = body

    def _compile_lookaround(self, node: Node) -> None:
        """Compile lookaround assertions."""
        if isinstance(node, LookAhead):
            self._emit(Inst(OpCode.LOOKAHEAD_START))
            self._compile(node.child)
            self._emit(Inst(OpCode.LOOKAHEAD_END))
        elif isinstance(node, NegLookAhead):
            self._emit(Inst(OpCode.NEG_LOOKAHEAD_START))
            self._compile(node.child)
            self._emit(Inst(OpCode.NEG_LOOKAHEAD_END))
        elif isinstance(node, (LookBehind, NegLookBehind)):
            self._emit(Inst(OpCode.LOOKBEHIND_START))
            self._compile(node.child)
            self._emit(Inst(OpCode.LOOKBEHIND_END))


def build_program(pattern: Pattern) -> Program:
    """Build a VM program from a pattern.

    Args:
        pattern: The parsed regex pattern.

    Returns:
        The compiled program.
    """
    builder = ProgramBuilder(pattern.flags)
    return builder.build(pattern)
