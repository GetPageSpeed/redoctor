"""Tests for the regex parser."""

import pytest

from redoctor.parser.parser import parse
from redoctor.parser.flags import Flags
from redoctor.parser.ast import (
    Pattern,
    Disjunction,
    Sequence,
    Empty,
    Capture,
    NamedCapture,
    NonCapture,
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
    LookAhead,
    NegLookAhead,
    LookBehind,
    NegLookBehind,
    Backref,
    NamedBackref,
    LineStart,
    LineEnd,
    has_backreferences,
    has_lookaround,
    count_captures,
)
from redoctor.exceptions import ParseError


class TestBasicParsing:
    """Test basic pattern parsing."""

    def test_empty_pattern(self):
        result = parse("")
        assert isinstance(result, Pattern)
        assert isinstance(result.node, Empty)

    def test_single_char(self):
        result = parse("a")
        assert isinstance(result.node, Char)
        assert result.node.char == ord("a")

    def test_sequence(self):
        result = parse("abc")
        assert isinstance(result.node, Sequence)
        assert len(result.node.nodes) == 3

    def test_disjunction(self):
        result = parse("a|b|c")
        assert isinstance(result.node, Disjunction)
        assert len(result.node.alternatives) == 3

    def test_dot(self):
        result = parse(".")
        assert isinstance(result.node, Dot)

    def test_anchors(self):
        result = parse("^a$")
        assert isinstance(result.node, Sequence)
        assert isinstance(result.node.nodes[0], LineStart)
        assert isinstance(result.node.nodes[2], LineEnd)


class TestQuantifiers:
    """Test quantifier parsing."""

    def test_star(self):
        result = parse("a*")
        assert isinstance(result.node, Star)
        assert isinstance(result.node.child, Char)

    def test_plus(self):
        result = parse("a+")
        assert isinstance(result.node, Plus)

    def test_question(self):
        result = parse("a?")
        assert isinstance(result.node, Question)

    def test_lazy_star(self):
        result = parse("a*?")
        assert isinstance(result.node, Star)
        assert result.node.greedy is False

    def test_lazy_plus(self):
        result = parse("a+?")
        assert isinstance(result.node, Plus)
        assert result.node.greedy is False

    def test_quantifier_exact(self):
        result = parse("a{3}")
        assert isinstance(result.node, Quantifier)
        assert result.node.min == 3
        assert result.node.max == 3

    def test_quantifier_range(self):
        result = parse("a{2,5}")
        assert isinstance(result.node, Quantifier)
        assert result.node.min == 2
        assert result.node.max == 5

    def test_quantifier_unbounded(self):
        result = parse("a{2,}")
        assert isinstance(result.node, Quantifier)
        assert result.node.min == 2
        assert result.node.max is None


class TestGroups:
    """Test group parsing."""

    def test_capture(self):
        result = parse("(a)")
        assert isinstance(result.node, Capture)
        assert result.node.index == 1

    def test_non_capture(self):
        result = parse("(?:a)")
        assert isinstance(result.node, NonCapture)

    def test_named_capture(self):
        result = parse("(?P<name>a)")
        assert isinstance(result.node, NamedCapture)
        assert result.node.name == "name"

    def test_nested_groups(self):
        result = parse("((a)(b))")
        assert isinstance(result.node, Capture)
        assert count_captures(result.node) == 3


class TestCharacterClasses:
    """Test character class parsing."""

    def test_simple_class(self):
        result = parse("[abc]")
        assert isinstance(result.node, CharClass)
        assert len(result.node.items) == 3

    def test_negated_class(self):
        result = parse("[^abc]")
        assert isinstance(result.node, CharClass)
        assert result.node.negated is True

    def test_range(self):
        result = parse("[a-z]")
        assert isinstance(result.node, CharClass)
        assert isinstance(result.node.items[0], CharClassRange)

    def test_word_char(self):
        result = parse(r"\w")
        assert isinstance(result.node, WordChar)

    def test_digit_char(self):
        result = parse(r"\d")
        assert isinstance(result.node, DigitChar)

    def test_space_char(self):
        result = parse(r"\s")
        assert isinstance(result.node, SpaceChar)


class TestLookaround:
    """Test lookaround assertions."""

    def test_lookahead(self):
        result = parse("(?=a)")
        assert isinstance(result.node, LookAhead)

    def test_neg_lookahead(self):
        result = parse("(?!a)")
        assert isinstance(result.node, NegLookAhead)

    def test_lookbehind(self):
        result = parse("(?<=a)")
        assert isinstance(result.node, LookBehind)

    def test_neg_lookbehind(self):
        result = parse("(?<!a)")
        assert isinstance(result.node, NegLookBehind)


class TestBackreferences:
    """Test backreference parsing."""

    def test_numeric_backref(self):
        result = parse(r"(a)\1")
        assert isinstance(result.node, Sequence)
        assert isinstance(result.node.nodes[1], Backref)
        assert result.node.nodes[1].index == 1

    def test_named_backref(self):
        result = parse(r"(?P<foo>a)(?P=foo)")
        assert isinstance(result.node, Sequence)
        assert isinstance(result.node.nodes[1], NamedBackref)


class TestEscapes:
    """Test escape sequence parsing."""

    def test_common_escapes(self):
        result = parse(r"\n\r\t")
        assert isinstance(result.node, Sequence)
        assert result.node.nodes[0].char == ord("\n")
        assert result.node.nodes[1].char == ord("\r")
        assert result.node.nodes[2].char == ord("\t")

    def test_hex_escape(self):
        result = parse(r"\x41")
        assert isinstance(result.node, Char)
        assert result.node.char == 0x41  # 'A'

    def test_special_char_escape(self):
        result = parse(r"\.")
        assert isinstance(result.node, Char)
        assert result.node.char == ord(".")


class TestFlags:
    """Test flag parsing."""

    def test_flags_from_string(self):
        flags = Flags.from_string("imsx")
        assert flags.ignore_case is True
        assert flags.multiline is True
        assert flags.dotall is True
        assert flags.verbose is True

    def test_flags_merge(self):
        f1 = Flags(ignore_case=True)
        f2 = Flags(multiline=True)
        merged = f1 | f2
        assert merged.ignore_case is True
        assert merged.multiline is True


class TestHelperFunctions:
    """Test AST helper functions."""

    def test_has_backreferences(self):
        result = parse(r"(a)\1")
        assert has_backreferences(result.node) is True

        result = parse(r"(a)")
        assert has_backreferences(result.node) is False

    def test_has_lookaround(self):
        result = parse(r"(?=a)")
        assert has_lookaround(result.node) is True

        result = parse(r"(a)")
        assert has_lookaround(result.node) is False

    def test_count_captures(self):
        result = parse(r"((a)(b)(c))")
        assert count_captures(result.node) == 4


class TestParseErrors:
    """Test parser error handling."""

    def test_unmatched_paren(self):
        with pytest.raises(ParseError):
            parse("(abc")

    def test_nothing_to_repeat(self):
        with pytest.raises(ParseError):
            parse("*")

    def test_invalid_quantifier(self):
        with pytest.raises(ParseError):
            parse("a{abc}")

    def test_unclosed_char_class(self):
        with pytest.raises(ParseError):
            parse("[abc")
