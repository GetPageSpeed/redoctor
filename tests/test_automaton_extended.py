"""Extended automaton tests for increased coverage."""


from redoctor.parser.parser import parse
from redoctor.automaton.eps_nfa import EpsNFA, State, Transition, TransitionType
from redoctor.automaton.eps_nfa_builder import build_eps_nfa
from redoctor.automaton.ordered_nfa import OrderedNFA, NFAStatePair, build_product_nfa
from redoctor.automaton.complexity_analyzer import AmbiguityWitness
from redoctor.automaton.witness import WitnessGenerator, generate_attack_from_witness
from redoctor.automaton.checker import AutomatonChecker, check_with_automaton
from redoctor.diagnostics.complexity import Complexity
from redoctor.unicode.ichar import IChar
from redoctor.config import Config


class TestStateExtended:
    """Extended state tests."""

    def test_repr_with_label(self):
        s = State(1, "test")
        assert "test" in repr(s)

    def test_repr_without_label(self):
        s = State(1)
        assert "1" in repr(s)


class TestTransitionExtended:
    """Extended transition tests."""

    def test_repr_epsilon(self):
        s1 = State(0)
        s2 = State(1)
        t = Transition(s1, s2, TransitionType.EPSILON)
        assert "ε" in repr(t) or "eps" in repr(t).lower()

    def test_repr_char(self):
        s1 = State(0)
        s2 = State(1)
        t = Transition(s1, s2, TransitionType.CHAR, IChar.from_char("a"))
        assert repr(t) is not None

    def test_repr_assert(self):
        s1 = State(0)
        s2 = State(1)
        t = Transition(s1, s2, TransitionType.ASSERT)
        assert "assert" in repr(t).lower()


class TestEpsNFAExtended:
    """Extended epsilon-NFA tests."""

    def test_char_transitions_from(self):
        nfa = EpsNFA()
        s1 = nfa.new_state()
        s2 = nfa.new_state()
        nfa.add_char(s1, s2, IChar.from_char("a"))
        nfa.initial = s1

        trans = nfa.char_transitions_from({s1})
        assert len(trans) > 0

    def test_get_alphabet(self):
        nfa = EpsNFA()
        s1 = nfa.new_state()
        s2 = nfa.new_state()
        nfa.add_char(s1, s2, IChar.from_char("a"))
        nfa.add_char(s1, s2, IChar.from_char("b"))

        alphabet = nfa.get_alphabet()
        assert len(alphabet) == 2

    def test_reverse(self):
        nfa = EpsNFA()
        s1 = nfa.new_state()
        s2 = nfa.new_state()
        nfa.initial = s1
        nfa.accepting.add(s2)
        nfa.add_char(s1, s2, IChar.from_char("a"))

        reversed_nfa = nfa.reverse()
        assert reversed_nfa.initial is not None
        assert len(reversed_nfa.accepting) > 0


class TestNFABuilderExtended:
    """Extended NFA builder tests."""

    def test_build_backref(self):
        pattern = parse(r"(a)\1")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_named_capture(self):
        pattern = parse(r"(?P<name>abc)")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_non_capture(self):
        pattern = parse(r"(?:abc)")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_flags_group(self):
        pattern = parse(r"(?i:abc)")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_flags_only(self):
        pattern = parse(r"(?i)")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_atomic_group(self):
        pattern = parse(r"(?>abc)")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_lookahead(self):
        pattern = parse(r"(?=abc)")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_lookbehind(self):
        pattern = parse(r"(?<=abc)")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_unicode_property(self):
        from redoctor.parser.ast import UnicodeProperty, Pattern
        from redoctor.parser.flags import Flags

        prop = UnicodeProperty("Letter", negated=False)
        pattern = Pattern(prop, Flags(), "")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0

    def test_build_negated_unicode_property(self):
        from redoctor.parser.ast import UnicodeProperty, Pattern
        from redoctor.parser.flags import Flags

        prop = UnicodeProperty("Letter", negated=True)
        pattern = Pattern(prop, Flags(), "")
        nfa = build_eps_nfa(pattern)
        assert nfa.size() > 0


class TestOrderedNFAExtended:
    """Extended ordered NFA tests."""

    def test_get_char_transitions(self):
        pattern = parse("a")
        eps_nfa = build_eps_nfa(pattern)
        ordered = OrderedNFA.from_eps_nfa(eps_nfa)

        if ordered.initial:
            _ = ordered.get_char_transitions(ordered.initial, ord("a"))
            # May or may not have transitions depending on structure


class TestNFAStatePair:
    """Test NFAStatePair."""

    def test_repr(self):
        s1 = State(0)
        s2 = State(1)
        pair = NFAStatePair(s1, s2)
        assert "0" in repr(pair)
        assert "1" in repr(pair)


class TestProductNFA:
    """Test product NFA construction."""

    def test_build_product_empty(self):
        nfa = OrderedNFA()
        nfa.initial = None
        trans, reachable = build_product_nfa(nfa)
        assert len(trans) == 0
        assert len(reachable) == 0


class TestWitnessGenerator:
    """Test witness generator."""

    def test_generate_attack_pattern(self):
        witness = AmbiguityWitness(
            prefix=[ord("x")],
            pump=[ord("a"), ord("a")],
            suffix=[ord("!")],
            state1=State(0),
            state2=State(1),
        )
        generator = WitnessGenerator(witness, Complexity.exponential())
        pattern = generator.generate_attack_pattern()
        assert pattern.prefix == "x"
        assert pattern.pump == "aa"
        assert pattern.suffix == "!"

    def test_generate_attack_string(self):
        witness = AmbiguityWitness(
            prefix=[],
            pump=[ord("a")],
            suffix=[ord("!")],
            state1=State(0),
            state2=State(1),
        )
        generator = WitnessGenerator(witness, Complexity.exponential())
        attack = generator.generate_attack_string(repeat=5)
        assert attack == "aaaaa!"

    def test_generate_empty_pump(self):
        witness = AmbiguityWitness(
            prefix=[],
            pump=[],
            suffix=[],
            state1=State(0),
            state2=State(1),
        )
        generator = WitnessGenerator(witness, Complexity.exponential())
        pattern = generator.generate_attack_pattern()
        assert pattern.pump == "a"  # Default

    def test_generate_attack_from_witness_none(self):
        result = generate_attack_from_witness(None, Complexity.safe())
        assert result is None


class TestAutomatonChecker:
    """Test automaton checker."""

    def test_check_with_automaton_function(self):
        result = check_with_automaton(r"^[a-z]+$")
        assert result is not None

    def test_check_parse_error(self):
        checker = AutomatonChecker()
        result = checker.check("(unclosed")
        assert result.error is not None

    def test_check_with_backreference(self):
        checker = AutomatonChecker()
        result = checker.check(r"(a)\1")
        # Should return unknown for backrefs
        assert "backref" in result.message.lower() or result.status.value == "unknown"

    def test_can_analyze(self):
        checker = AutomatonChecker()
        pattern = parse(r"^[a-z]+$")
        assert checker.can_analyze(pattern)

        pattern_with_backref = parse(r"(a)\1")
        assert not checker.can_analyze(pattern_with_backref)

    def test_check_large_nfa(self):
        # Create a config with small max NFA size
        config = Config(max_nfa_size=5)
        checker = AutomatonChecker(config)
        result = checker.check(r"^[a-z]+[0-9]+[a-z]+$")
        # Should handle gracefully
        assert result is not None
