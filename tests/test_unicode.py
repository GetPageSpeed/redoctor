"""Tests for Unicode handling."""

import pytest

from redoctor.unicode.uchar import UChar
from redoctor.unicode.ichar import IChar
from redoctor.unicode.icharset import ICharSet
from redoctor.unicode.ustring import UString


class TestUChar:
    """Test Unicode code point wrapper."""

    def test_creation(self):
        c = UChar(65)
        assert c.value == 65
        assert str(c) == "A"

    def test_from_char(self):
        c = UChar.from_char("A")
        assert c.value == 65

    def test_invalid_codepoint(self):
        with pytest.raises(ValueError):
            UChar(-1)
        with pytest.raises(ValueError):
            UChar(0x110000)

    def test_comparison(self):
        a = UChar(65)
        b = UChar(66)
        assert a < b
        assert a == UChar(65)

    def test_is_word_char(self):
        assert UChar.from_char("a").is_word_char()
        assert UChar.from_char("0").is_word_char()
        assert UChar.from_char("_").is_word_char()
        assert not UChar.from_char("!").is_word_char()

    def test_case_conversion(self):
        a = UChar.from_char("a")
        assert a.to_upper().value == ord("A")
        assert a.to_upper().to_lower() == a


class TestIChar:
    """Test interval-based character class."""

    def test_from_char(self):
        c = IChar.from_char("a")
        assert "a" in c
        assert "b" not in c

    def test_from_range(self):
        c = IChar.from_range(ord("a"), ord("z"))
        assert "a" in c
        assert "m" in c
        assert "z" in c
        assert "A" not in c

    def test_empty(self):
        c = IChar.empty()
        assert not c
        assert "a" not in c

    def test_any(self):
        c = IChar.any()
        assert "a" in c
        assert "\n" not in c

        c_dotall = IChar.any(dotall=True)
        assert "\n" in c_dotall

    def test_predefined_classes(self):
        assert "0" in IChar.digit()
        assert "a" not in IChar.digit()

        assert "a" in IChar.word()
        assert "_" in IChar.word()
        assert "!" not in IChar.word()

        assert " " in IChar.space()
        assert "\t" in IChar.space()
        assert "a" not in IChar.space()

    def test_union(self):
        a = IChar.from_char("a")
        b = IChar.from_char("b")
        ab = a.union(b)
        assert "a" in ab
        assert "b" in ab
        assert "c" not in ab

    def test_intersect(self):
        letters = IChar.from_range(ord("a"), ord("z"))
        word = IChar.word()
        result = letters.intersect(word)
        assert "a" in result
        assert "0" not in result

    def test_negate(self):
        a = IChar.from_char("a")
        not_a = a.negate()
        assert "a" not in not_a
        assert "b" in not_a

    def test_size(self):
        letters = IChar.from_range(ord("a"), ord("z"))
        assert letters.size() == 26

    def test_sample(self):
        c = IChar.from_range(ord("a"), ord("z"))
        sample = c.sample()
        assert sample == ord("a")


class TestICharSet:
    """Test character set with partitions."""

    def test_empty(self):
        cs = ICharSet.empty()
        assert len(cs) == 0

    def test_from_ichars(self):
        a = IChar.from_char("a")
        b = IChar.from_char("b")
        cs = ICharSet.from_ichars([a, b])
        assert len(cs) >= 1

    def test_add(self):
        cs = ICharSet.empty()
        cs = cs.add(IChar.from_char("a"))
        assert len(cs) >= 1

    def test_sample_each(self):
        a = IChar.from_char("a")
        b = IChar.from_char("b")
        cs = ICharSet.from_ichars([a, b])
        samples = cs.sample_each()
        assert len(samples) >= 1


class TestUString:
    """Test Unicode string utilities."""

    def test_from_str(self):
        s = UString.from_str("hello")
        assert str(s) == "hello"
        assert len(s) == 5

    def test_empty(self):
        s = UString.empty()
        assert s.is_empty()
        assert len(s) == 0

    def test_iteration(self):
        s = UString.from_str("abc")
        chars = list(s)
        assert chars == [ord("a"), ord("b"), ord("c")]

    def test_concat(self):
        a = UString.from_str("hello")
        b = UString.from_str(" world")
        c = a + b
        assert str(c) == "hello world"

    def test_repeat(self):
        s = UString.from_str("ab")
        r = s.repeat(3)
        assert str(r) == "ababab"

    def test_slice(self):
        s = UString.from_str("hello")
        assert str(s.slice(1, 4)) == "ell"

    def test_reverse(self):
        s = UString.from_str("abc")
        r = s.reverse()
        assert str(r) == "cba"

    def test_append(self):
        s = UString.from_str("ab")
        s2 = s.append(ord("c"))
        assert str(s2) == "abc"
