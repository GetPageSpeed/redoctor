"""Ordered NFA with priority-aware transitions."""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple

from redoctor.automaton.eps_nfa import EpsNFA, State, Transition, TransitionType
from redoctor.unicode.ichar import IChar


@dataclass
class OrderedNFA:
    """NFA with ordered (prioritized) transitions.

    This is used for analyzing backtracking behavior where
    transition order matters.

    Attributes:
        states: Set of all states.
        initial: Initial state.
        accepting: Set of accepting states.
        transitions: Transitions grouped by source state and ordered by priority.
    """

    states: Set[State] = field(default_factory=set)
    initial: Optional[State] = None
    accepting: Set[State] = field(default_factory=set)
    transitions: Dict[State, List[Transition]] = field(default_factory=dict)

    @classmethod
    def from_eps_nfa(cls, eps_nfa: EpsNFA) -> "OrderedNFA":
        """Convert an epsilon-NFA to an ordered NFA by eliminating epsilon transitions."""
        ordered = cls()
        ordered.states = set(eps_nfa.states)
        ordered.initial = eps_nfa.initial
        ordered.accepting = set(eps_nfa.accepting)

        # Build epsilon closures for each state
        closures: Dict[State, Set[State]] = {}
        for state in eps_nfa.states:
            closures[state] = eps_nfa.epsilon_closure({state})

        # For each state, collect character transitions reachable through epsilon
        for state in eps_nfa.states:
            ordered.transitions[state] = []

            # Collect all transitions from epsilon closure
            trans_by_priority: Dict[int, List[Transition]] = {}
            for closure_state in closures[state]:
                for trans in eps_nfa.transitions_from(closure_state):
                    if trans.type == TransitionType.CHAR:
                        # Create new transition to epsilon closure of target
                        for target in closures[trans.target]:
                            new_trans = Transition(
                                source=state,
                                target=target,
                                type=TransitionType.CHAR,
                                char=trans.char,
                                priority=trans.priority,
                            )
                            prio = trans.priority
                            if prio not in trans_by_priority:
                                trans_by_priority[prio] = []
                            trans_by_priority[prio].append(new_trans)

            # Sort by priority and add
            for prio in sorted(trans_by_priority.keys()):
                ordered.transitions[state].extend(trans_by_priority[prio])

            # Check if any state in epsilon closure is accepting
            if closures[state] & eps_nfa.accepting:
                ordered.accepting.add(state)

        return ordered

    def get_transitions(self, state: State) -> List[Transition]:
        """Get transitions from a state in priority order."""
        return self.transitions.get(state, [])

    def get_char_transitions(self, state: State, c: int) -> List[Transition]:
        """Get transitions matching a character."""
        result = []
        for trans in self.get_transitions(state):
            if trans.matches(c):
                result.append(trans)
        return result

    def size(self) -> int:
        """Return number of states."""
        return len(self.states)

    def transition_count(self) -> int:
        """Return total number of transitions."""
        return sum(len(t) for t in self.transitions.values())


@dataclass(frozen=True)
class NFAStatePair:
    """A pair of NFA states for product automaton construction."""

    state1: State
    state2: State

    def __repr__(self) -> str:
        return f"({self.state1.id}, {self.state2.id})"


def build_product_nfa(
    nfa: OrderedNFA,
) -> Tuple[Dict[NFAStatePair, List[Tuple[IChar, NFAStatePair]]], Set[NFAStatePair]]:
    """Build a product automaton for ambiguity detection.

    The product automaton has states (q1, q2) where q1 and q2 are states
    from the original NFA. An accepting state in the product means
    there are two different paths to reach the same state.

    Returns:
        Tuple of (transitions dict, set of reachable pairs).
    """
    if nfa.initial is None:
        return {}, set()

    transitions: Dict[NFAStatePair, List[Tuple[IChar, NFAStatePair]]] = {}
    visited: Set[NFAStatePair] = set()
    stack: List[NFAStatePair] = []

    initial_pair = NFAStatePair(nfa.initial, nfa.initial)
    stack.append(initial_pair)

    while stack:
        pair = stack.pop()
        if pair in visited:
            continue
        visited.add(pair)

        trans1 = nfa.get_transitions(pair.state1)
        trans2 = nfa.get_transitions(pair.state2)

        pair_transitions: List[Tuple[IChar, NFAStatePair]] = []

        for t1 in trans1:
            for t2 in trans2:
                if t1.char and t2.char:
                    # Check if characters overlap
                    overlap = t1.char.intersect(t2.char)
                    if overlap:
                        next_pair = NFAStatePair(t1.target, t2.target)
                        pair_transitions.append((overlap, next_pair))
                        if next_pair not in visited:
                            stack.append(next_pair)

        if pair_transitions:
            transitions[pair] = pair_transitions

    return transitions, visited
