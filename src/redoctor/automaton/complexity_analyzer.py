"""Complexity analysis using automata theory."""

from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple
from collections import deque

from redoctor.automaton.eps_nfa import EpsNFA, State
from redoctor.automaton.ordered_nfa import OrderedNFA, NFAStatePair, build_product_nfa
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
    state1: State
    state2: State


class ComplexityAnalyzer:
    """Analyzes regex complexity using automata-theoretic methods."""

    def __init__(self, eps_nfa: EpsNFA):
        self.eps_nfa = eps_nfa
        self.ordered_nfa = OrderedNFA.from_eps_nfa(eps_nfa)

    def analyze(self) -> Tuple[Complexity, Optional[AmbiguityWitness]]:
        """Analyze the complexity of the regex.

        Returns:
            Tuple of (complexity, optional witness).
        """
        # Check for exponential ambiguity (EDA)
        eda_witness = self._check_exponential_ambiguity()
        if eda_witness:
            return Complexity.exponential(), eda_witness

        # Check for polynomial ambiguity (IDA)
        ida_result = self._check_polynomial_ambiguity()
        if ida_result:
            degree, witness = ida_result
            return Complexity.polynomial(degree), witness

        return Complexity.safe(), None

    def _check_exponential_ambiguity(self) -> Optional[AmbiguityWitness]:
        """Check for Exponential Degree Ambiguity (EDA).

        EDA occurs when there exists a state q and a string w such that
        there are exponentially many paths from initial to q reading w.
        This is detected by finding a "pump" in the product automaton
        where both components can diverge and then reconverge.
        """
        if self.ordered_nfa.initial is None:
            return None

        # Build product automaton
        product_trans, reachable = build_product_nfa(self.ordered_nfa)

        # Look for pairs (q1, q2) where q1 != q2 and there's a cycle
        # back to a pair with the same property
        divergent_pairs = []
        for pair in reachable:
            if pair.state1 == pair.state2:
                continue
            divergent_pairs.append(pair)

        # Only check for cycles if we have divergent pairs with actual transitions
        for pair in divergent_pairs:
            # Check if this pair has a path back to itself or to another divergent pair
            cycle = self._find_cycle_in_product(pair, product_trans)
            if cycle and len(cycle) > 0:
                # Found potential EDA - verify it's a real cycle
                prefix = self._find_path_to_pair(pair, product_trans)
                suffix = self._find_path_to_accepting(pair, product_trans)
                return AmbiguityWitness(
                    prefix=prefix,
                    pump=cycle,
                    suffix=suffix,
                    state1=pair.state1,
                    state2=pair.state2,
                )

        return None

    def _check_polynomial_ambiguity(self) -> Optional[Tuple[int, AmbiguityWitness]]:
        """Check for Infinite Degree Ambiguity (IDA) - polynomial complexity.

        IDA occurs when there's a cycle that can be taken different
        numbers of times. The degree depends on the number of nested loops.
        """
        if self.ordered_nfa.initial is None:
            return None

        # Find loops in the NFA
        loops = self._find_loops()
        if not loops:
            return None

        # Check for overlapping loops (polynomial degree = number of overlaps + 1)
        # Only consider it polynomial if there are multiple overlapping loops
        degree = self._compute_loop_overlap_degree(loops)
        if degree > 1 and len(loops) > 1:
            # Find a witness - only if we have actual overlapping loops
            loop = loops[0] if loops else None
            if loop:
                witness = AmbiguityWitness(
                    prefix=[],
                    pump=[ord("a")],  # Simplified
                    suffix=[ord("!")],
                    state1=loop[0],
                    state2=loop[0],
                )
                return degree, witness

        return None

    def _find_cycle_in_product(
        self,
        start: NFAStatePair,
        transitions: Dict[NFAStatePair, List[Tuple[IChar, NFAStatePair]]],
    ) -> List[int]:
        """Find a cycle starting and ending at the given pair."""
        visited: Set[NFAStatePair] = set()
        stack: List[Tuple[NFAStatePair, List[int]]] = [(start, [])]

        while stack:
            pair, chars = stack.pop()

            if pair == start and chars:
                return chars

            if pair in visited and pair != start:
                continue
            visited.add(pair)

            for char, next_pair in transitions.get(pair, []):
                sample = char.sample()
                if sample is not None:
                    stack.append((next_pair, chars + [sample]))

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

    def _find_loops(self) -> List[List[State]]:
        """Find all loops in the NFA."""
        if self.ordered_nfa.initial is None:
            return []

        loops: List[List[State]] = []
        visited: Set[State] = set()
        rec_stack: Set[State] = set()
        path: List[State] = []

        def dfs(state: State) -> None:
            visited.add(state)
            rec_stack.add(state)
            path.append(state)

            for trans in self.ordered_nfa.get_transitions(state):
                if trans.target not in visited:
                    dfs(trans.target)
                elif trans.target in rec_stack:
                    # Found a loop
                    loop_start = path.index(trans.target)
                    loops.append(path[loop_start:] + [trans.target])

            path.pop()
            rec_stack.remove(state)

        dfs(self.ordered_nfa.initial)
        return loops

    def _compute_loop_overlap_degree(self, loops: List[List[State]]) -> int:
        """Compute the degree of overlap between loops."""
        if not loops:
            return 1

        # Check how many loops share states
        state_to_loops: Dict[State, List[int]] = {}
        for i, loop in enumerate(loops):
            for state in loop:
                if state not in state_to_loops:
                    state_to_loops[state] = []
                state_to_loops[state].append(i)

        max_overlap = (
            max(len(v) for v in state_to_loops.values()) if state_to_loops else 1
        )
        return max(max_overlap, 1)
