"""Complexity analysis using automata theory."""

from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple
from collections import deque

from redoctor.automaton.eps_nfa import EpsNFA, State
from redoctor.automaton.ordered_nfa import OrderedNFA, NFAStatePair, build_product_nfa
from redoctor.automaton.scc_checker import check_with_scc, MatchMode
from redoctor.diagnostics.complexity import Complexity
from redoctor.unicode.ichar import IChar


@dataclass
class AmbiguityWitness:
    """Witness for ambiguity in the NFA.

    Attributes:
        prefix: Path to reach the ambiguous state.
        pump: The repeating path (loop).
        suffix: Path to reach accepting state.
        state1: First state in the ambiguous pair.
        state2: Second state in the ambiguous pair.
    """

    prefix: List[int]
    pump: List[int]
    suffix: List[int]
    state1: Optional[State] = None
    state2: Optional[State] = None


class ComplexityAnalyzer:
    """Analyzes regex complexity using automata-theoretic methods.

    Uses the proper SCC-based algorithm from recheck for precise detection:
    - No false negatives (detects all real vulnerabilities)
    - Configurable false positive handling based on match context
    """

    def __init__(
        self,
        eps_nfa: EpsNFA,
        match_mode: MatchMode = MatchMode.AUTO,
        has_end_anchor: bool = False,
        requires_continuation: bool = False,
    ):
        """Initialize the complexity analyzer.

        Args:
            eps_nfa: The epsilon-NFA to analyze.
            match_mode: How the regex is expected to be used.
                - AUTO: Check for anchors to determine if patterns can escape early
                - FULL: Assume full-string matching (conservative, may have FPs)
                - PARTIAL: Assume partial matching (fewer FPs for NGINX etc.)
            has_end_anchor: Whether the pattern has an end anchor ($ or \\Z).
            requires_continuation: Whether the pattern has required content
                after quantified groups (e.g., ^([^@]+)+@).
        """
        self.eps_nfa = eps_nfa
        self.match_mode = match_mode
        self.has_end_anchor = has_end_anchor
        self.requires_continuation = requires_continuation
        self.ordered_nfa = OrderedNFA.from_eps_nfa(eps_nfa)

    def analyze(self) -> Tuple[Complexity, Optional[AmbiguityWitness]]:
        """Analyze the complexity of the regex.

        Uses a hybrid approach:
        1. SCC-based check for exponential (EDA) using NFAwLA
        2. Product automaton for polynomial (IDA) detection

        Returns:
            Tuple of (complexity, optional witness).
        """
        if self.ordered_nfa.initial is None:
            return Complexity.safe(), None

        # Step 1: Check for exponential (EDA) using SCC-based approach
        # This uses NFAwLA which preserves multi-transition info for EDA detection
        complexity, scc_witness = check_with_scc(
            self.eps_nfa,
            match_mode=self.match_mode,
            has_end_anchor=self.has_end_anchor,
            requires_continuation=self.requires_continuation,
        )

        if complexity.type.value != "safe":
            if scc_witness is not None:
                witness = AmbiguityWitness(
                    prefix=scc_witness.prefix,
                    pump=scc_witness.pump,
                    suffix=scc_witness.suffix,
                )
                return complexity, witness
            return complexity, None

        # Step 2: Check for polynomial (IDA) using product automaton
        # The SCC checker handles EDA well, but IDA needs product automaton
        product_trans, reachable = build_product_nfa(self.ordered_nfa)

        # Find divergent pairs (states where the two components differ)
        divergent_pairs = [p for p in reachable if p.state1 != p.state2]

        if not divergent_pairs:
            return Complexity.safe(), None

        # Check for polynomial ambiguity (divergent pairs with bidirectional cycles)
        ida_result = self._check_polynomial_ambiguity_with_product(
            divergent_pairs, product_trans
        )
        if ida_result:
            degree, witness = ida_result
            return Complexity.polynomial(degree), witness

        return Complexity.safe(), None

    def _check_polynomial_ambiguity_with_product(
        self,
        divergent_pairs: List[NFAStatePair],
        product_trans: Dict[NFAStatePair, List[Tuple[IChar, NFAStatePair]]],
    ) -> Optional[Tuple[int, AmbiguityWitness]]:
        """Check for polynomial ambiguity using product automaton.

        Polynomial ambiguity (IDA) requires that the divergent pairs are part
        of a feedback structure where divergence can accumulate with input length.

        This requires BIDIRECTIONAL connectivity:
        1. A cycle can reach divergent pairs (divergence is created)
        2. Divergent pairs can reach back to a cycle (divergence accumulates)

        For patterns like ^[a-z]+foo$, the divergent pairs are reachable from
        a cycle but can't reach back to any cycle - they're "dead ends" and
        represent finite O(1) ambiguity.

        For patterns like ^.*a.*a$, the divergent pairs have cycles themselves
        (detected as EDA), or can feed back into cycles (polynomial).
        """
        if not divergent_pairs:
            return None

        # Find all pairs that have cycles (can reach themselves)
        pairs_with_cycles: Set[NFAStatePair] = set()
        for pair in product_trans:
            cycle = self._find_cycle_in_product(pair, product_trans)
            if cycle:
                pairs_with_cycles.add(pair)

        if not pairs_with_cycles:
            # No cycles at all in the product automaton
            # The divergent pairs represent finite ambiguity, not polynomial
            return None

        # Check for polynomial ambiguity: divergent pairs that are BOTH
        # reachable from AND can reach back to a cycling structure
        for div_pair in divergent_pairs:
            # Check if this divergent pair is reachable from any cycle
            reachable_from_cycle = False
            for cycling_pair in pairs_with_cycles:
                if self._can_reach(cycling_pair, div_pair, product_trans):
                    reachable_from_cycle = True
                    break

            if not reachable_from_cycle:
                continue

            # Check if this divergent pair can reach back to any cycle
            can_reach_cycle = False
            for cycling_pair in pairs_with_cycles:
                if self._can_reach(div_pair, cycling_pair, product_trans):
                    can_reach_cycle = True
                    break

            if can_reach_cycle:
                # Found polynomial ambiguity: bidirectional connectivity
                # This means the divergence can be created and accumulated
                degree = min(len(divergent_pairs) + 1, 4)

                prefix = self._find_path_to_pair(div_pair, product_trans)
                suffix = self._find_path_to_accepting(div_pair, product_trans)

                sample_char = ord("a")
                for char, _ in product_trans.get(div_pair, []):
                    s = char.sample()
                    if s is not None:
                        sample_char = s
                        break

                witness = AmbiguityWitness(
                    prefix=prefix,
                    pump=[sample_char],
                    suffix=suffix,
                    state1=div_pair.state1,
                    state2=div_pair.state2,
                )
                return degree, witness

        # Divergent pairs exist but don't have bidirectional cycle connectivity
        # This is finite ambiguity, not polynomial
        return None

    def _can_reach(
        self,
        start: NFAStatePair,
        target: NFAStatePair,
        transitions: Dict[NFAStatePair, List[Tuple[IChar, NFAStatePair]]],
    ) -> bool:
        """Check if target is reachable from start in the product automaton."""
        if start == target:
            return True

        visited: Set[NFAStatePair] = set()
        queue: deque[NFAStatePair] = deque([start])

        while queue:
            pair = queue.popleft()
            if pair == target:
                return True
            if pair in visited:
                continue
            visited.add(pair)

            for _, next_pair in transitions.get(pair, []):
                if next_pair not in visited:
                    queue.append(next_pair)

        return False

    def _find_cycle_in_product(
        self,
        start: NFAStatePair,
        transitions: Dict[NFAStatePair, List[Tuple[IChar, NFAStatePair]]],
    ) -> List[int]:
        """Find a cycle starting and ending at the given pair.

        Uses BFS from the immediate successors of *start* so that each
        intermediate node is visited at most once while still allowing
        multiple successors to independently search for a path back.
        """
        # Seed the BFS with all direct successors of start
        queue: deque[Tuple[NFAStatePair, List[int]]] = deque()
        for char, next_pair in transitions.get(start, []):
            sample = char.sample()
            if sample is not None:
                queue.append((next_pair, [sample]))

        visited: Set[NFAStatePair] = set()

        while queue:
            pair, chars = queue.popleft()

            if pair == start:
                return chars

            if pair in visited:
                continue
            visited.add(pair)

            for char, next_pair in transitions.get(pair, []):
                sample = char.sample()
                if sample is not None:
                    queue.append((next_pair, chars + [sample]))

        return []

    def _find_path_to_pair(
        self,
        target: NFAStatePair,
        transitions: Dict[NFAStatePair, List[Tuple[IChar, NFAStatePair]]],
    ) -> List[int]:
        """Find a path from initial to the target pair."""
        if self.ordered_nfa.initial is None:
            return []

        initial = NFAStatePair(self.ordered_nfa.initial, self.ordered_nfa.initial)
        if initial == target:
            return []

        visited: Set[NFAStatePair] = set()
        queue: deque[Tuple[NFAStatePair, List[int]]] = deque([(initial, [])])

        while queue:
            pair, path = queue.popleft()
            if pair == target:
                return path
            if pair in visited:
                continue
            visited.add(pair)

            for char, next_pair in transitions.get(pair, []):
                sample = char.sample()
                if sample is not None:
                    queue.append((next_pair, path + [sample]))

        return []

    def _find_path_to_accepting(
        self,
        start: NFAStatePair,
        transitions: Dict[NFAStatePair, List[Tuple[IChar, NFAStatePair]]],
    ) -> List[int]:
        """Find a path from start to an accepting state."""
        visited: Set[NFAStatePair] = set()
        queue: deque[Tuple[NFAStatePair, List[int]]] = deque([(start, [])])

        while queue:
            pair, path = queue.popleft()

            # Check if either state is accepting
            if pair.state1 in self.ordered_nfa.accepting:
                # Need to find a non-matching suffix
                return path + [ord("!")]

            if pair in visited:
                continue
            visited.add(pair)

            for char, next_pair in transitions.get(pair, []):
                sample = char.sample()
                if sample is not None:
                    queue.append((next_pair, path + [sample]))

        return [ord("!")]
