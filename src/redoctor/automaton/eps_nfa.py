"""Epsilon-NFA (Non-deterministic Finite Automaton with epsilon transitions)."""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from enum import Enum, auto

from redoctor.unicode.ichar import IChar


class TransitionType(Enum):
    """Type of transition."""

    EPSILON = auto()  # Epsilon transition (no input consumed)
    CHAR = auto()  # Character transition
    ASSERT = auto()  # Assertion (zero-width)


@dataclass(frozen=True)
class State:
    """A state in the automaton.

    Attributes:
        id: Unique identifier for the state.
        label: Optional label for debugging.
    """

    id: int
    label: str = ""

    def __repr__(self) -> str:
        if self.label:
            return f"State({self.id}, {self.label!r})"
        return f"State({self.id})"

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, State):
            return self.id == other.id
        return False


@dataclass(frozen=True)
class Transition:
    """A transition in the automaton.

    Attributes:
        source: Source state.
        target: Target state.
        type: Type of transition.
        char: Character class for CHAR transitions.
        priority: Priority for ordered transitions (lower = higher priority).
    """

    source: State
    target: State
    type: TransitionType = TransitionType.EPSILON
    char: Optional[IChar] = None
    priority: int = 0

    def __repr__(self) -> str:
        if self.type == TransitionType.EPSILON:
            return f"{self.source.id} --ε-> {self.target.id}"
        elif self.type == TransitionType.CHAR:
            return f"{self.source.id} --{self.char}-> {self.target.id}"
        else:
            return f"{self.source.id} --assert-> {self.target.id}"

    def is_epsilon(self) -> bool:
        return self.type == TransitionType.EPSILON

    def matches(self, c: int) -> bool:
        """Check if this transition matches a character."""
        if self.type != TransitionType.CHAR or self.char is None:
            return False
        return c in self.char


@dataclass
class EpsNFA:
    """Epsilon-NFA representation.

    Attributes:
        states: Set of all states.
        initial: Initial state.
        accepting: Set of accepting states.
        transitions: List of all transitions.
    """

    states: Set[State] = field(default_factory=set)
    initial: Optional[State] = None
    accepting: Set[State] = field(default_factory=set)
    transitions: List[Transition] = field(default_factory=list)

    _next_id: int = field(default=0, repr=False)
    _trans_from: Dict[State, List[Transition]] = field(default_factory=dict, repr=False)
    _trans_to: Dict[State, List[Transition]] = field(default_factory=dict, repr=False)

    def new_state(self, label: str = "") -> State:
        """Create a new state."""
        state = State(self._next_id, label)
        self._next_id += 1
        self.states.add(state)
        return state

    def add_transition(self, transition: Transition) -> None:
        """Add a transition."""
        self.transitions.append(transition)
        if transition.source not in self._trans_from:
            self._trans_from[transition.source] = []
        self._trans_from[transition.source].append(transition)
        if transition.target not in self._trans_to:
            self._trans_to[transition.target] = []
        self._trans_to[transition.target].append(transition)

    def add_epsilon(self, source: State, target: State, priority: int = 0) -> None:
        """Add an epsilon transition."""
        self.add_transition(
            Transition(source, target, TransitionType.EPSILON, priority=priority)
        )

    def add_char(
        self, source: State, target: State, char: IChar, priority: int = 0
    ) -> None:
        """Add a character transition."""
        self.add_transition(
            Transition(source, target, TransitionType.CHAR, char, priority)
        )

    def transitions_from(self, state: State) -> List[Transition]:
        """Get all transitions from a state."""
        return self._trans_from.get(state, [])

    def transitions_to(self, state: State) -> List[Transition]:
        """Get all transitions to a state."""
        return self._trans_to.get(state, [])

    def epsilon_closure(self, states: Set[State]) -> Set[State]:
        """Compute the epsilon closure of a set of states."""
        closure = set(states)
        stack = list(states)

        while stack:
            state = stack.pop()
            for trans in self.transitions_from(state):
                if trans.is_epsilon() and trans.target not in closure:
                    closure.add(trans.target)
                    stack.append(trans.target)

        return closure

    def char_transitions_from(self, states: Set[State]) -> Dict[IChar, Set[State]]:
        """Get character transitions from a set of states, grouped by character class."""
        result: Dict[IChar, Set[State]] = {}
        for state in states:
            for trans in self.transitions_from(state):
                if trans.type == TransitionType.CHAR and trans.char:
                    if trans.char not in result:
                        result[trans.char] = set()
                    result[trans.char].add(trans.target)
        return result

    def size(self) -> int:
        """Return the number of states."""
        return len(self.states)

    def transition_count(self) -> int:
        """Return the number of transitions."""
        return len(self.transitions)

    def accepts(self, string: List[int]) -> bool:
        """Check if the automaton accepts a string (list of code points)."""
        current = self.epsilon_closure({self.initial}) if self.initial else set()

        for c in string:
            next_states: Set[State] = set()
            for state in current:
                for trans in self.transitions_from(state):
                    if trans.type == TransitionType.CHAR and trans.matches(c):
                        next_states.add(trans.target)
            current = self.epsilon_closure(next_states)
            if not current:
                return False

        return bool(current & self.accepting)

    def get_alphabet(self) -> Set[IChar]:
        """Get the alphabet (set of all character classes used)."""
        alphabet: Set[IChar] = set()
        for trans in self.transitions:
            if trans.type == TransitionType.CHAR and trans.char:
                alphabet.add(trans.char)
        return alphabet

    def reverse(self) -> "EpsNFA":
        """Create a reversed automaton (swap initial and accepting, reverse transitions)."""
        reversed_nfa = EpsNFA()

        # Copy states
        state_map = {}
        for state in self.states:
            new_state = reversed_nfa.new_state(state.label)
            state_map[state] = new_state

        # New initial state connected to all accepting states
        new_initial = reversed_nfa.new_state("rev_init")
        reversed_nfa.initial = new_initial
        for acc in self.accepting:
            reversed_nfa.add_epsilon(new_initial, state_map[acc])

        # Original initial becomes accepting
        if self.initial:
            reversed_nfa.accepting.add(state_map[self.initial])

        # Reverse all transitions
        for trans in self.transitions:
            reversed_nfa.add_transition(
                Transition(
                    source=state_map[trans.target],
                    target=state_map[trans.source],
                    type=trans.type,
                    char=trans.char,
                    priority=trans.priority,
                )
            )

        return reversed_nfa
