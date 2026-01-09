"""Extended parser tests for increased coverage."""

import pytest

from redoctor.parser.parser import parse
from redoctor.parser.flags import Flags
from redoctor.parser.ast import (
    Char,
    Dot,
    CharClass,
    CharClassRange,
    Sequence,
    Empty,
    Star,
    Plus,
    Question,
    Quantifier,
    FlagsGroup,
    AtomicGroup,
    Backref,
    NamedBackref,
    LineStart,
    LineEnd,
    StringStart,
    StringEnd,
    WordBoundary,
    is_quantifiable,
)
from redoctor.exceptions import ParseError


class TestFlagsExtended:
    """Extended flags tests."""

    def test_from_re_flags(self):
        import re

        flags = Flags.from_re_flags(re.IGNORECASE | re.MULTILINE)
        assert flags.ignore_case
        assert flags.multiline

    def test_to_re_flags(self):
        import re

        flags = Flags(ignore_case=True, multiline=True, dotall=True)
        re_flags = flags.to_re_flags()
        assert re_flags & re.IGNORECASE
        assert re_flags & re.MULTILINE
        assert re_flags & re.DOTALL

    def test_all_flags(self):
        flags = Flags(
            ignore_case=True,
            multiline=True,
            dotall=True,
            unicode=True,
            ascii=True,
            verbose=True,
        )
        re_flags = flags.to_re_flags()
        assert re_flags != 0


class TestParserEscapes:
    """Test escape sequences."""

    def test_unicode_escape_u(self):
        result = parse(r"\u0041")
        assert isinstance(result.node, Char)
        assert result.node.char == 0x41

    def test_unicode_escape_U(self):
        result = parse(r"\U00000041")
        assert isinstance(result.node, Char)
        assert result.node.char == 0x41

    def test_bell_escape(self):
        result = parse(r"\a")
        assert isinstance(result.node, Char)
        assert result.node.char == ord("\a")

    def test_null_escape(self):
        result = parse(r"\0")
        assert isinstance(result.node, Char)
        assert result.node.char == 0

    def test_string_start(self):
        result = parse(r"\A")
        assert isinstance(result.node, StringStart)

    def test_string_end(self):
        result = parse(r"\Z")
        assert isinstance(result.node, StringEnd)

    def test_g_backref(self):
        result = parse(r"(a)\g<1>")
        assert isinstance(result.node, Sequence)
        assert isinstance(result.node.nodes[1], Backref)

    def test_g_named_backref(self):
        result = parse(r"(?P<foo>a)\g<foo>")
        assert isinstance(result.node, Sequence)
        assert isinstance(result.node.nodes[1], NamedBackref)


class TestCharClassExtended:
    """Extended character class tests."""

    def test_class_with_literal_bracket(self):
        result = parse("[]]")
        assert isinstance(result.node, CharClass)

    def test_class_with_escape(self):
        result = parse(r"[\n\t]")
        assert isinstance(result.node, CharClass)

    def test_class_with_hex_escape(self):
        result = parse(r"[\x41]")
        assert isinstance(result.node, CharClass)

    def test_class_with_dash_at_end(self):
        result = parse("[a-]")
        assert isinstance(result.node, CharClass)

    def test_class_with_predefined(self):
        result = parse(r"[\w\d]")
        assert isinstance(result.node, CharClass)


class TestGroupsExtended:
    """Extended group tests."""

    def test_flag_only_group(self):
        result = parse("(?i)")
        assert isinstance(result.node, FlagsGroup)

    def test_flag_with_pattern(self):
        result = parse("(?i:abc)")
        assert isinstance(result.node, FlagsGroup)
        assert result.node.child is not None

    def test_negative_flag(self):
        result = parse("(?-i:abc)")
        assert isinstance(result.node, FlagsGroup)

    def test_atomic_group(self):
        result = parse("(?>abc)")
        assert isinstance(result.node, AtomicGroup)


class TestQuantifierExtended:
    """Extended quantifier tests."""

    def test_possessive_star(self):
        result = parse("a*+")
        assert isinstance(result.node, Star)
        assert result.node.possessive

    def test_possessive_plus(self):
        result = parse("a++")
        assert isinstance(result.node, Plus)
        assert result.node.possessive

    def test_possessive_question(self):
        result = parse("a?+")
        assert isinstance(result.node, Question)
        assert result.node.possessive


class TestASTHelpers:
    """Test AST helper functions."""

    def test_is_quantifiable(self):
        assert is_quantifiable(Char(ord("a")))
        assert is_quantifiable(Dot())
        assert not is_quantifiable(LineStart())
        assert not is_quantifiable(LineEnd())
        assert not is_quantifiable(WordBoundary())
        assert not is_quantifiable(Empty())

    def test_node_walk(self):
        result = parse("(a|b)+")
        nodes = list(result.node.walk())
        assert len(nodes) > 1

    def test_node_children(self):
        result = parse("(a|b)")
        children = result.node.children()
        assert len(children) > 0


class TestNodeRepresentations:
    """Test node __repr__ methods."""

    def test_char_repr(self):
        c = Char(ord("a"))
        assert "a" in repr(c)

    def test_char_repr_nonprintable(self):
        c = Char(0)
        assert "0x" in repr(c)

    def test_dot_repr(self):
        d = Dot()
        assert "Dot" in repr(d)

    def test_charclass_repr(self):
        cc = CharClass([Char(ord("a"))], negated=True)
        assert "CharClass" in repr(cc)

    def test_range_repr(self):
        r = CharClassRange(ord("a"), ord("z"))
        assert "Range" in repr(r)

    def test_quantifier_repr(self):
        q = Quantifier(Char(ord("a")), min=2, max=5)
        assert "{2,5}" in repr(q)

    def test_quantifier_repr_unbounded(self):
        q = Quantifier(Char(ord("a")), min=2, max=None)
        assert "∞" in repr(q)


class TestErrorCases:
    """Test error handling."""

    def test_trailing_backslash(self):
        with pytest.raises(ParseError):
            parse("\\")

    def test_trailing_backslash_in_class(self):
        with pytest.raises(ParseError):
            parse("[\\")

    def test_unterminated_group_name(self):
        with pytest.raises(ParseError):
            parse("(?P<name")

    def test_unknown_group_type(self):
        with pytest.raises(ParseError):
            parse("(?Z)")
