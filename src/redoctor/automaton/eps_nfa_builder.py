"""Build epsilon-NFA from regex AST using Thompson construction."""


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
    UnicodeProperty,
)
from redoctor.parser.flags import Flags
from redoctor.automaton.eps_nfa import EpsNFA, State
from redoctor.unicode.ichar import IChar


class EpsNFABuilder:
    """Builds an epsilon-NFA from a regex AST."""

    def __init__(self, flags: Flags = None):
        self.nfa = EpsNFA()
        self.flags = flags or Flags()
        self.priority = 0

    def build(self, pattern: Pattern) -> EpsNFA:
        """Build an epsilon-NFA from a pattern."""
        self.flags = pattern.flags
        initial = self.nfa.new_state("init")
        self.nfa.initial = initial

        final = self.nfa.new_state("final")
        self.nfa.accepting.add(final)

        self._build_node(pattern.node, initial, final)
        return self.nfa

    def _build_node(self, node: Node, start: State, end: State) -> None:
        """Build NFA fragment for a node."""
        if isinstance(node, Empty):
            self.nfa.add_epsilon(start, end)

        elif isinstance(node, Char):
            self._build_char(node, start, end)

        elif isinstance(node, Dot):
            self._build_dot(node, start, end)

        elif isinstance(node, CharClass):
            self._build_char_class(node, start, end)

        elif isinstance(node, (WordChar, DigitChar, SpaceChar)):
            self._build_predefined_class(node, start, end)

        elif isinstance(node, Disjunction):
            self._build_disjunction(node, start, end)

        elif isinstance(node, Sequence):
            self._build_sequence(node, start, end)

        elif isinstance(node, (Capture, NamedCapture, NonCapture)):
            self._build_node(node.child, start, end)

        elif isinstance(node, FlagsGroup):
            if node.child:
                self._build_node(node.child, start, end)
            else:
                self.nfa.add_epsilon(start, end)

        elif isinstance(node, AtomicGroup):
            # Atomic groups are approximated as regular groups for NFA
            self._build_node(node.child, start, end)

        elif isinstance(node, Star):
            self._build_star(node, start, end)

        elif isinstance(node, Plus):
            self._build_plus(node, start, end)

        elif isinstance(node, Question):
            self._build_question(node, start, end)

        elif isinstance(node, Quantifier):
            self._build_quantifier(node, start, end)

        elif isinstance(
            node,
            (LineStart, LineEnd, StringStart, StringEnd, WordBoundary, NonWordBoundary),
        ):
            # Assertions are zero-width, treated as epsilon
            self.nfa.add_epsilon(start, end)

        elif isinstance(node, (LookAhead, NegLookAhead, LookBehind, NegLookBehind)):
            # Lookaround is approximated as epsilon for basic NFA
            # Full support requires NFAwLA
            self.nfa.add_epsilon(start, end)

        elif isinstance(node, (Backref, NamedBackref)):
            # Backreferences are approximated as .* for NFA analysis
            # This is conservative - actual implementation uses VM
            loop = self.nfa.new_state("backref_loop")
            self.nfa.add_epsilon(start, loop)
            self.nfa.add_epsilon(loop, end)
            self.nfa.add_char(loop, loop, IChar.any())

        elif isinstance(node, UnicodeProperty):
            # Unicode properties are approximated
            if node.negated:
                self.nfa.add_char(start, end, IChar.any())
            else:
                self.nfa.add_char(start, end, IChar.any())

        else:
            # Unknown node type - treat as epsilon
            self.nfa.add_epsilon(start, end)

    def _build_char(self, node: Char, start: State, end: State) -> None:
        """Build NFA for a single character."""
        char = IChar.from_char(node.char)
        if self.flags.ignore_case:
            # Add case-folded variants
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
        self.nfa.add_char(start, end, char)

    def _build_dot(self, node: Dot, start: State, end: State) -> None:
        """Build NFA for dot (any character)."""
        char = IChar.any(dotall=node.dotall or self.flags.dotall)
        self.nfa.add_char(start, end, char)

    def _build_char_class(self, node: CharClass, start: State, end: State) -> None:
        """Build NFA for a character class."""
        char = self._compute_char_class(node)
        if node.negated:
            char = char.negate()
        self.nfa.add_char(start, end, char)

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

    def _build_predefined_class(self, node: Node, start: State, end: State) -> None:
        r"""Build NFA for predefined character classes (\d, \w, \s)."""
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
        self.nfa.add_char(start, end, char)

    def _build_disjunction(self, node: Disjunction, start: State, end: State) -> None:
        """Build NFA for alternation (|)."""
        for i, alt in enumerate(node.alternatives):
            alt_start = self.nfa.new_state(f"alt{i}_start")
            alt_end = self.nfa.new_state(f"alt{i}_end")
            self.nfa.add_epsilon(start, alt_start, priority=i)
            self._build_node(alt, alt_start, alt_end)
            self.nfa.add_epsilon(alt_end, end)

    def _build_sequence(self, node: Sequence, start: State, end: State) -> None:
        """Build NFA for a sequence (concatenation)."""
        if not node.nodes:
            self.nfa.add_epsilon(start, end)
            return

        current = start
        for i, child in enumerate(node.nodes):
            if i == len(node.nodes) - 1:
                next_state = end
            else:
                next_state = self.nfa.new_state(f"seq{i}")
            self._build_node(child, current, next_state)
            current = next_state

    def _build_star(self, node: Star, start: State, end: State) -> None:
        """Build NFA for * (zero or more)."""
        loop_start = self.nfa.new_state("star_start")
        loop_end = self.nfa.new_state("star_end")

        if node.greedy:
            # Greedy: try loop first
            self.nfa.add_epsilon(start, loop_start, priority=0)
            self.nfa.add_epsilon(start, end, priority=1)
        else:
            # Lazy: try skip first
            self.nfa.add_epsilon(start, end, priority=0)
            self.nfa.add_epsilon(start, loop_start, priority=1)

        self._build_node(node.child, loop_start, loop_end)

        if node.greedy:
            self.nfa.add_epsilon(loop_end, loop_start, priority=0)
            self.nfa.add_epsilon(loop_end, end, priority=1)
        else:
            self.nfa.add_epsilon(loop_end, end, priority=0)
            self.nfa.add_epsilon(loop_end, loop_start, priority=1)

    def _build_plus(self, node: Plus, start: State, end: State) -> None:
        """Build NFA for + (one or more)."""
        loop_start = self.nfa.new_state("plus_start")
        loop_end = self.nfa.new_state("plus_end")

        self.nfa.add_epsilon(start, loop_start)
        self._build_node(node.child, loop_start, loop_end)

        if node.greedy:
            self.nfa.add_epsilon(loop_end, loop_start, priority=0)
            self.nfa.add_epsilon(loop_end, end, priority=1)
        else:
            self.nfa.add_epsilon(loop_end, end, priority=0)
            self.nfa.add_epsilon(loop_end, loop_start, priority=1)

    def _build_question(self, node: Question, start: State, end: State) -> None:
        """Build NFA for ? (zero or one)."""
        if node.greedy:
            inner_start = self.nfa.new_state("opt_start")
            self.nfa.add_epsilon(start, inner_start, priority=0)
            self.nfa.add_epsilon(start, end, priority=1)
            self._build_node(node.child, inner_start, end)
        else:
            inner_start = self.nfa.new_state("opt_start")
            self.nfa.add_epsilon(start, end, priority=0)
            self.nfa.add_epsilon(start, inner_start, priority=1)
            self._build_node(node.child, inner_start, end)

    def _build_quantifier(self, node: Quantifier, start: State, end: State) -> None:
        """Build NFA for {n,m} quantifier."""
        min_count = node.min
        max_count = node.max

        current = start

        # Build min required copies
        for i in range(min_count):
            next_state = self.nfa.new_state(f"quant_req{i}")
            self._build_node(node.child, current, next_state)
            current = next_state

        if max_count is None:
            # Unbounded: add star-like loop
            loop_start = self.nfa.new_state("quant_loop_start")
            loop_end = self.nfa.new_state("quant_loop_end")

            if node.greedy:
                self.nfa.add_epsilon(current, loop_start, priority=0)
                self.nfa.add_epsilon(current, end, priority=1)
            else:
                self.nfa.add_epsilon(current, end, priority=0)
                self.nfa.add_epsilon(current, loop_start, priority=1)

            self._build_node(node.child, loop_start, loop_end)

            if node.greedy:
                self.nfa.add_epsilon(loop_end, loop_start, priority=0)
                self.nfa.add_epsilon(loop_end, end, priority=1)
            else:
                self.nfa.add_epsilon(loop_end, end, priority=0)
                self.nfa.add_epsilon(loop_end, loop_start, priority=1)
        else:
            # Bounded: add optional copies
            for i in range(min_count, max_count):
                next_state = self.nfa.new_state(f"quant_opt{i}")
                opt_start = self.nfa.new_state(f"quant_opt_start{i}")

                if node.greedy:
                    self.nfa.add_epsilon(current, opt_start, priority=0)
                    self.nfa.add_epsilon(current, end, priority=1)
                else:
                    self.nfa.add_epsilon(current, end, priority=0)
                    self.nfa.add_epsilon(current, opt_start, priority=1)

                self._build_node(node.child, opt_start, next_state)
                current = next_state

            self.nfa.add_epsilon(current, end)


def build_eps_nfa(pattern: Pattern) -> EpsNFA:
    """Build an epsilon-NFA from a pattern.

    Args:
        pattern: The parsed regex pattern.

    Returns:
        The constructed epsilon-NFA.
    """
    builder = EpsNFABuilder(pattern.flags)
    return builder.build(pattern)
