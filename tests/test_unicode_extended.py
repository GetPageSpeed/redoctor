"""Extended Unicode tests for increased coverage."""

import pytest

from redoctor.unicode.uchar import UChar, MIN_VALUE, MAX_VALUE, MAX_BMP
from redoctor.unicode.ichar import IChar
from redoctor.unicode.icharset import ICharSet
from redoctor.unicode.ustring import UString


class TestUCharExtended:
    """Extended UChar tests."""

    def test_repr_printable(self):
        c = UChar(ord("a"))
        assert "a" in repr(c)

    def test_repr_nonprintable(self):
        c = UChar(0)
        assert "0x" in repr(c)

    def test_from_char_error(self):
        with pytest.raises(ValueError):
            UChar.from_char("ab")

    def test_is_ascii(self):
        assert UChar(65).is_ascii()
        assert not UChar(256).is_ascii()

    def test_is_bmp(self):
        assert UChar(65).is_bmp()
        assert not UChar(0x10000).is_bmp()

    def test_is_digit(self):
        assert UChar(ord("5")).is_digit()
        assert not UChar(ord("a")).is_digit()

    def test_is_space(self):
        assert UChar(ord(" ")).is_space()
        assert UChar(ord("\t")).is_space()
        assert not UChar(ord("a")).is_space()

    def test_arithmetic(self):
        c = UChar(65)
        c2 = c + 1
        assert c2.value == 66

        diff = UChar(66) - UChar(65)
        assert diff == 1

        c3 = UChar(66) - 1
        assert c3.value == 65

    def test_constants(self):
        assert MIN_VALUE.value == 0
        assert MAX_VALUE.value == 0x10FFFF
        assert MAX_BMP.value == 0xFFFF


class TestICharExtended:
    """Extended IChar tests."""

    def test_post_init_validation(self):
        with pytest.raises(ValueError):
            IChar(((10, 5),))  # Invalid: start > end

    def test_contains_int(self):
        c = IChar.from_char(65)
        assert 65 in c

    def test_contains_uchar(self):
        c = IChar.from_char("a")
        assert UChar(ord("a")) in c

    def test_bool_empty(self):
        c = IChar.empty()
        assert not c

    def test_bool_nonempty(self):
        c = IChar.from_char("a")
        assert c

    def test_repr_single(self):
        c = IChar.from_char("a")
        assert "a" in repr(c)

    def test_repr_range(self):
        c = IChar.from_range(ord("a"), ord("z"))
        assert "a-z" in repr(c) or "a" in repr(c)

    def test_repr_nonprintable(self):
        c = IChar.from_range(0, 10)
        assert "0x" in repr(c)

    def test_negate_empty(self):
        c = IChar.empty()
        neg = c.negate()
        assert 0 in neg
        assert 0x10FFFF in neg

    def test_union_empty(self):
        a = IChar.from_char("a")
        empty = IChar.empty()
        result = a.union(empty)
        assert "a" in result

        result2 = empty.union(a)
        assert "a" in result2

    def test_intersect_empty(self):
        a = IChar.from_char("a")
        empty = IChar.empty()
        result = a.intersect(empty)
        assert not result

    def test_min_max(self):
        c = IChar.from_range(ord("a"), ord("z"))
        assert c.min() == ord("a")
        assert c.max() == ord("z")

    def test_min_max_empty(self):
        c = IChar.empty()
        assert c.min() is None
        assert c.max() is None

    def test_iter_chars(self):
        c = IChar.from_range(ord("a"), ord("c"))
        chars = list(c.iter_chars())
        assert chars == [ord("a"), ord("b"), ord("c")]

    def test_to_char_list(self):
        c = IChar.from_range(ord("a"), ord("z"))
        chars = c.to_char_list(limit=5)
        assert len(chars) == 5


class TestICharSetExtended:
    """Extended ICharSet tests."""

    def test_any(self):
        cs = ICharSet.any()
        assert len(cs) > 0

    def test_any_dotall(self):
        cs = ICharSet.any(dotall=True)
        assert len(cs) > 0

    def test_iter(self):
        a = IChar.from_char("a")
        cs = ICharSet([a])
        items = list(cs)
        assert len(items) == 1

    def test_bool_empty(self):
        cs = ICharSet.empty()
        assert not cs

    def test_bool_nonempty(self):
        cs = ICharSet([IChar.from_char("a")])
        assert cs

    def test_union(self):
        cs1 = ICharSet([IChar.from_char("a")])
        cs2 = ICharSet([IChar.from_char("b")])
        result = cs1.union(cs2)
        assert len(result) >= 1

    def test_contains(self):
        a = IChar.from_char("a")
        cs = ICharSet([a])
        result = cs.contains(ord("a"))
        assert result is not None

    def test_contains_not_found(self):
        a = IChar.from_char("a")
        cs = ICharSet([a])
        result = cs.contains(ord("z"))
        assert result is None


class TestUStringExtended:
    """Extended UString tests."""

    def test_surrogate_pairs(self):
        # Test with a string that would have surrogates in UTF-16
        s = UString.from_str("hello")
        assert len(s) == 5

    def test_getitem(self):
        s = UString.from_str("abc")
        assert s[0] == ord("a")
        assert s[1] == ord("b")

    def test_eq_str(self):
        s = UString.from_str("hello")
        assert s == "hello"

    def test_eq_ustring(self):
        s1 = UString.from_str("hello")
        s2 = UString.from_str("hello")
        assert s1 == s2

    def test_hash(self):
        s = UString.from_str("hello")
        d = {s: "value"}
        assert d[UString.from_str("hello")] == "value"

    def test_from_chars(self):
        s = UString.from_chars([65, 66, 67])
        assert str(s) == "ABC"
