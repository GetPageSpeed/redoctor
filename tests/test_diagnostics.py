"""Tests for diagnostic types."""


from redoctor.diagnostics.complexity import Complexity, ComplexityType
from redoctor.diagnostics.attack_pattern import AttackPattern
from redoctor.diagnostics.hotspot import Hotspot, HotspotSet
from redoctor.diagnostics.diagnostics import Diagnostics, Status


class TestComplexity:
    """Test complexity classification."""

    def test_safe(self):
        c = Complexity.safe()
        assert c.type == ComplexityType.SAFE
        assert c.is_safe
        assert not c.is_vulnerable

    def test_polynomial(self):
        c = Complexity.polynomial(2)
        assert c.type == ComplexityType.POLYNOMIAL
        assert c.degree == 2
        assert c.is_vulnerable
        assert c.is_polynomial

    def test_exponential(self):
        c = Complexity.exponential()
        assert c.type == ComplexityType.EXPONENTIAL
        assert c.is_vulnerable
        assert c.is_exponential

    def test_comparison(self):
        safe = Complexity.safe()
        poly = Complexity.polynomial(2)
        exp = Complexity.exponential()

        assert safe < poly
        assert poly < exp
        assert safe < exp

    def test_worse(self):
        safe = Complexity.safe()
        exp = Complexity.exponential()

        result = safe.worse(exp)
        assert result.is_exponential

    def test_str(self):
        c = Complexity.polynomial(2)
        assert "O(n^2)" in str(c)


class TestAttackPattern:
    """Test attack pattern representation."""

    def test_creation(self):
        ap = AttackPattern(prefix="x", pump="aa", suffix="!")
        assert ap.prefix == "x"
        assert ap.pump == "aa"
        assert ap.suffix == "!"

    def test_build(self):
        ap = AttackPattern(prefix="", pump="a", suffix="!")
        attack = ap.build(10)
        assert attack == "aaaaaaaaaa!"

    def test_simple(self):
        ap = AttackPattern.simple("a", "!")
        assert ap.prefix == ""
        assert ap.pump == "a"
        assert ap.suffix == "!"

    def test_attack_property(self):
        ap = AttackPattern(prefix="", pump="a", suffix="!", repeat=5)
        assert ap.attack == "aaaaa!"

    def test_with_repeat(self):
        ap = AttackPattern(prefix="", pump="a", suffix="!")
        ap2 = ap.with_repeat(10)
        assert ap2.repeat == 10
        assert ap2.attack == "aaaaaaaaaa!"


class TestHotspot:
    """Test hotspot detection."""

    def test_creation(self):
        h = Hotspot(start=5, end=10, pattern="^(a+)+$")
        assert h.start == 5
        assert h.end == 10

    def test_text(self):
        h = Hotspot(start=1, end=6, pattern="^(a+)+$")
        assert h.text == "(a+)+"

    def test_highlight(self):
        h = Hotspot(start=1, end=6, pattern="^(a+)+$")
        highlighted = h.highlight()
        assert "^(a+)+$" in highlighted
        assert "^^^^^" in highlighted

    def test_from_positions(self):
        h = Hotspot.from_positions([3, 4, 5], "^(a+)+$")
        assert h is not None
        assert h.start == 3
        assert h.end == 6


class TestHotspotSet:
    """Test hotspot set."""

    def test_empty(self):
        hs = HotspotSet.empty("test")
        assert len(hs) == 0
        assert not hs

    def test_add(self):
        hs = HotspotSet.empty("test pattern")
        h = Hotspot(0, 4, "test pattern")
        hs = hs.add(h)
        assert len(hs) == 1

    def test_primary(self):
        hs = HotspotSet.empty("test")
        h1 = Hotspot(0, 2, "test", temperature=0.5)
        h2 = Hotspot(2, 4, "test", temperature=1.0)
        hs = hs.add(h1).add(h2)
        assert hs.primary == h2


class TestDiagnostics:
    """Test diagnostic result."""

    def test_safe(self):
        d = Diagnostics.safe("^[a-z]+$")
        assert d.is_safe
        assert d.status == Status.SAFE
        assert d.complexity.is_safe

    def test_vulnerable(self):
        d = Diagnostics.vulnerable(
            source="^(a+)+$",
            complexity=Complexity.exponential(),
            attack_pattern=AttackPattern.simple("a", "!"),
        )
        assert d.is_vulnerable
        assert d.status == Status.VULNERABLE
        assert d.attack is not None

    def test_unknown(self):
        d = Diagnostics.unknown("complex pattern")
        assert d.status == Status.UNKNOWN
        assert not d.is_safe
        assert not d.is_vulnerable

    def test_from_error(self):
        d = Diagnostics.from_error("bad(pattern", "Unmatched paren")
        assert d.status == Status.ERROR
        assert d.error == "Unmatched paren"

    def test_to_dict(self):
        d = Diagnostics.vulnerable(
            source="^(a+)+$",
            complexity=Complexity.exponential(),
            attack_pattern=AttackPattern.simple("a", "!"),
        )
        data = d.to_dict()
        assert data["status"] == "vulnerable"
        assert "complexity" in data
        assert "attack" in data

    def test_str(self):
        d = Diagnostics.safe("^test$")
        s = str(d)
        assert "test" in s
        assert "safe" in s.lower()
