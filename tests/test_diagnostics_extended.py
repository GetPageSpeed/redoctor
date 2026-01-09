"""Extended diagnostics tests for increased coverage."""


from redoctor.diagnostics.complexity import Complexity
from redoctor.diagnostics.attack_pattern import AttackPattern
from redoctor.diagnostics.hotspot import Hotspot, HotspotSet
from redoctor.diagnostics.diagnostics import Diagnostics


class TestComplexityExtended:
    """Extended complexity tests."""

    def test_repr(self):
        c = Complexity.safe()
        assert "safe" in repr(c)

        c = Complexity.polynomial(3)
        assert "polynomial" in repr(c)
        assert "3" in repr(c)

        c = Complexity.exponential()
        assert "exponential" in repr(c)

    def test_comparison_polynomial_degrees(self):
        p2 = Complexity.polynomial(2)
        p3 = Complexity.polynomial(3)
        assert p2 < p3

    def test_comparison_equal(self):
        s1 = Complexity.safe()
        s2 = Complexity.safe()
        assert not (s1 < s2)

    def test_worse_same_type(self):
        p2 = Complexity.polynomial(2)
        p3 = Complexity.polynomial(3)
        result = p2.worse(p3)
        assert result.degree == 3


class TestAttackPatternExtended:
    """Extended attack pattern tests."""

    def test_str_long_pump(self):
        ap = AttackPattern(prefix="", pump="a" * 50, suffix="!")
        s = str(ap)
        assert "..." in s

    def test_str_short_pump(self):
        ap = AttackPattern(prefix="x", pump="ab", suffix="!")
        s = str(ap)
        assert "ab" in s


class TestHotspotExtended:
    """Extended hotspot tests."""

    def test_repr(self):
        h = Hotspot(start=1, end=5, pattern="test pattern")
        assert "1:5" in repr(h)

    def test_str(self):
        h = Hotspot(start=0, end=4, pattern="test")
        assert str(h) == "test"

    def test_from_positions_empty(self):
        h = Hotspot.from_positions([], "test")
        assert h is None


class TestHotspotSetExtended:
    """Extended hotspot set tests."""

    def test_iter(self):
        hs = HotspotSet.empty("test")
        h = Hotspot(0, 2, "test")
        hs = hs.add(h)
        items = list(hs)
        assert len(items) == 1

    def test_primary_empty(self):
        hs = HotspotSet.empty("test")
        assert hs.primary is None


class TestDiagnosticsExtended:
    """Extended diagnostics tests."""

    def test_attack_no_pattern(self):
        d = Diagnostics.safe("test")
        assert d.attack is None

    def test_to_dict_with_all_fields(self):
        d = Diagnostics.vulnerable(
            source="^(a+)+$",
            complexity=Complexity.exponential(),
            attack_pattern=AttackPattern.simple("a", "!"),
            hotspot=Hotspot(1, 6, "^(a+)+$"),
            checker="automaton",
        )
        data = d.to_dict()
        assert "hotspot" in data
        assert "checker" in data

    def test_to_dict_error(self):
        d = Diagnostics.from_error("bad", "error message")
        data = d.to_dict()
        assert data["error"] == "error message"

    def test_to_dict_minimal(self):
        d = Diagnostics.safe("test")
        data = d.to_dict()
        assert data["status"] == "safe"
