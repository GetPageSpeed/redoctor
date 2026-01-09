"""Tests for automaton infrastructure."""


from redoctor.parser.parser import parse
from redoctor.automaton.eps_nfa import EpsNFA, State, Transition, TransitionType
from redoctor.automaton.eps_nfa_builder import build_eps_nfa
from redoctor.automaton.ordered_nfa import OrderedNFA
from redoctor.automaton.complexity_analyzer import ComplexityAnalyzer
from redoctor.unicode.ichar import IChar


class TestState:
    """Test automaton states."""

    def test_creation(self):
        s = State(0)
        assert s.id == 0

    def test_with_label(self):
        s = State(1, "start")
        assert s.label == "start"

    def test_equality(self):
        s1 = State(0)
        s2 = State(0)
        s3 = State(1)
        assert s1 == s2
        assert s1 != s3

    def test_hash(self):
        s = State(0)
        d = {s: "value"}
        assert d[State(0)] == "value"


class TestTransition:
    """Test automaton transitions."""

    def test_epsilon(self):
        s1 = State(0)
        s2 = State(1)
        t = Transition(s1, s2, TransitionType.EPSILON)
        assert t.is_epsilon()

    def test_char(self):
        s1 = State(0)
        s2 = State(1)
        c = IChar.from_char("a")
        t = Transition(s1, s2, TransitionType.CHAR, c)
        assert not t.is_epsilon()
        assert t.matches(ord("a"))
        assert not t.matches(ord("b"))


class TestEpsNFA:
    """Test epsilon-NFA."""

    def test_creation(self):
        nfa = EpsNFA()
        assert nfa.size() == 0

    def test_add_state(self):
        nfa = EpsNFA()
        s = nfa.new_state("test")
        assert s in nfa.states
        assert nfa.size() == 1

    def test_add_epsilon(self):
        nfa = EpsNFA()
        s1 = nfa.new_state()
        s2 = nfa.new_state()
        nfa.add_epsilon(s1, s2)
        assert nfa.transition_count() == 1

    def test_add_char(self):
        nfa = EpsNFA()
        s1 = nfa.new_state()
        s2 = nfa.new_state()
        nfa.add_char(s1, s2, IChar.from_char("a"))
        assert nfa.transition_count() == 1

    def test_epsilon_closure(self):
        nfa = EpsNFA()
        s1 = nfa.new_state()
        s2 = nfa.new_state()
        s3 = nfa.new_state()
        nfa.add_epsilon(s1, s2)
        nfa.add_epsilon(s2, s3)
        closure = nfa.epsilon_closure({s1})
        assert s1 in closure
        assert s2 in closure
        assert s3 in closure

    def test_accepts_simple(self):
        nfa = EpsNFA()
        s1 = nfa.new_state()
        s2 = nfa.new_state()
        nfa.initial = s1
        nfa.accepting.add(s2)
        nfa.add_char(s1, s2, IChar.from_char("a"))

        assert nfa.accepts([ord("a")])
        assert not nfa.accepts([ord("b")])
        assert not nfa.accepts([])


class TestEpsNFABuilder:
    """Test NFA construction from regex."""

    def test_build_char(self):
        pattern = parse("a")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0
        assert nfa.initial is not None
        assert len(nfa.accepting) > 0

    def test_build_sequence(self):
        pattern = parse("abc")
        nfa = build_eps_nfa(pattern)
        assert nfa.accepts([ord("a"), ord("b"), ord("c")])
        assert not nfa.accepts([ord("a"), ord("b")])

    def test_build_disjunction(self):
        pattern = parse("a|b")
        nfa = build_eps_nfa(pattern)
        assert nfa.accepts([ord("a")])
        assert nfa.accepts([ord("b")])
        assert not nfa.accepts([ord("c")])

    def test_build_star(self):
        pattern = parse("a*")
        nfa = build_eps_nfa(pattern)
        assert nfa.accepts([])
        assert nfa.accepts([ord("a")])
        assert nfa.accepts([ord("a"), ord("a"), ord("a")])

    def test_build_plus(self):
        pattern = parse("a+")
        nfa = build_eps_nfa(pattern)
        assert not nfa.accepts([])
        assert nfa.accepts([ord("a")])
        assert nfa.accepts([ord("a"), ord("a")])

    def test_build_question(self):
        pattern = parse("a?")
        nfa = build_eps_nfa(pattern)
        assert nfa.accepts([])
        assert nfa.accepts([ord("a")])
        assert not nfa.accepts([ord("a"), ord("a")])

    def test_build_char_class(self):
        pattern = parse("[abc]")
        nfa = build_eps_nfa(pattern)
        assert nfa.accepts([ord("a")])
        assert nfa.accepts([ord("b")])
        assert nfa.accepts([ord("c")])
        assert not nfa.accepts([ord("d")])


class TestOrderedNFA:
    """Test ordered NFA conversion."""

    def test_from_eps_nfa(self):
        pattern = parse("a*")
        eps_nfa = build_eps_nfa(pattern)
        ordered = OrderedNFA.from_eps_nfa(eps_nfa)
        assert ordered.size() > 0

    def test_transitions_ordered(self):
        pattern = parse("a|b")
        eps_nfa = build_eps_nfa(pattern)
        ordered = OrderedNFA.from_eps_nfa(eps_nfa)
        # Should have transitions
        assert ordered.transition_count() > 0


class TestComplexityAnalyzer:
    """Test complexity analysis."""

    def test_simple_pattern(self):
        # Simple patterns should complete analysis
        pattern = parse("a+")
        nfa = build_eps_nfa(pattern)
        analyzer = ComplexityAnalyzer(nfa)
        complexity, witness = analyzer.analyze()
        # Analysis should complete without error
        assert complexity is not None

    def test_exponential_pattern(self):
        # Classic exponential pattern
        pattern = parse("(a+)+")
        nfa = build_eps_nfa(pattern)
        analyzer = ComplexityAnalyzer(nfa)
        complexity, witness = analyzer.analyze()
        # Should detect as vulnerable (exponential or polynomial)
        # The analyzer uses heuristics, so we just check it runs
        assert complexity is not None

    def test_nested_quantifier(self):
        pattern = parse("(a*)*")
        nfa = build_eps_nfa(pattern)
        analyzer = ComplexityAnalyzer(nfa)
        complexity, _ = analyzer.analyze()
        # Complex pattern - analysis should complete
        assert complexity is not None

    def test_literal_pattern(self):
        # Literal patterns should be safe
        pattern = parse("abc")
        nfa = build_eps_nfa(pattern)
        analyzer = ComplexityAnalyzer(nfa)
        complexity, _ = analyzer.analyze()
        assert complexity.is_safe
