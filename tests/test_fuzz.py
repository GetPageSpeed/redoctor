"""Tests for the fuzzing module."""


from redoctor.parser.parser import parse
from redoctor.fuzz.fstring import FString
from redoctor.fuzz.seeder import StaticSeeder, DynamicSeeder
from redoctor.fuzz.mutators import RandomMutator, PumpMutator, CombinedMutator
from redoctor.fuzz.checker import FuzzChecker
from redoctor.config import Config


class TestFString:
    """Test fuzzing string representation."""

    def test_creation(self):
        s = FString([ord("a"), ord("b"), ord("c")])
        assert str(s) == "abc"
        assert len(s) == 3

    def test_from_str(self):
        s = FString.from_str("hello")
        assert str(s) == "hello"

    def test_empty(self):
        s = FString.empty()
        assert len(s) == 0
        assert str(s) == ""

    def test_copy(self):
        s = FString.from_str("test")
        c = s.copy()
        assert str(c) == "test"
        assert c is not s

    def test_insert(self):
        s = FString.from_str("ac")
        s2 = s.insert(1, ord("b"))
        assert str(s2) == "abc"

    def test_delete(self):
        s = FString.from_str("abc")
        s2 = s.delete(1)
        assert str(s2) == "ac"

    def test_replace(self):
        s = FString.from_str("abc")
        s2 = s.replace(1, ord("x"))
        assert str(s2) == "axc"

    def test_append(self):
        s = FString.from_str("ab")
        s2 = s.append(ord("c"))
        assert str(s2) == "abc"

    def test_concat(self):
        s1 = FString.from_str("ab")
        s2 = FString.from_str("cd")
        s3 = s1.concat(s2)
        assert str(s3) == "abcd"

    def test_repeat_expansion(self):
        s = FString.from_str("abcd")
        s = s.with_repeat(1, 3, 1)  # "bc" is the pump
        expanded = s.expand_repeat(3)
        assert str(expanded) == "abcbcbcd"


class TestStaticSeeder:
    """Test static seed generation."""

    def test_generate_seeds(self):
        pattern = parse("a+")
        seeder = StaticSeeder(max_seeds=10)
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_matching_strings(self):
        pattern = parse("[abc]+")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        # Should have seeds that contain a, b, or c
        all_chars = set()
        for seed in seeds:
            for c in seed.chars:
                all_chars.add(c)
        assert ord("a") in all_chars or ord("b") in all_chars or ord("c") in all_chars

    def test_generate_with_quantifiers(self):
        pattern = parse("a*b+")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0


class TestDynamicSeeder:
    """Test dynamic seed generation."""

    def test_generate_seeds(self):
        pattern = parse("a+")
        seeder = DynamicSeeder(max_seeds=10)
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_refine_seeds(self):
        seeder = DynamicSeeder()
        seed = FString.from_str("aaaa!")
        refined = seeder.refine(seed, steps=5000, target_steps=10000)
        # Should produce some refined seeds
        assert isinstance(refined, list)


class TestRandomMutator:
    """Test random mutation strategies."""

    def test_mutate(self):
        mutator = RandomMutator(seed=42, mutations_per_string=5)
        s = FString.from_str("abc")
        mutations = mutator.mutate(s)
        assert len(mutations) == 5

    def test_mutate_empty(self):
        mutator = RandomMutator(seed=42)
        s = FString.empty()
        mutations = mutator.mutate(s)
        # Should still produce mutations
        assert len(mutations) > 0


class TestPumpMutator:
    """Test pump-focused mutations."""

    def test_mutate(self):
        mutator = PumpMutator(max_pump_length=5)
        s = FString.from_str("aaa")
        mutations = mutator.mutate(s)
        assert len(mutations) > 0
        # Should have some expanded versions
        assert any(len(m) > len(s) for m in mutations)


class TestCombinedMutator:
    """Test combined mutation strategies."""

    def test_mutate(self):
        mutator = CombinedMutator(seed=42)
        s = FString.from_str("abc")
        mutations = mutator.mutate(s)
        assert len(mutations) > 0


class TestFuzzChecker:
    """Test fuzz-based vulnerability checker."""

    def test_check_safe_pattern(self):
        checker = FuzzChecker(Config.quick())
        result = checker.check(r"^[a-z]+$")
        # Simple patterns should be safe
        assert result.status.value in ("safe", "unknown")

    def test_check_vulnerable_pattern(self):
        config = Config(
            timeout=2.0,
            max_iterations=1000,
        )
        checker = FuzzChecker(config)
        result = checker.check(r"^(a+)+$")
        # May or may not detect with limited iterations
        # Just check it doesn't crash
        assert result is not None

    def test_check_with_char_class(self):
        checker = FuzzChecker(Config.quick())
        result = checker.check(r"^[a-zA-Z0-9]+$")
        assert result.status.value in ("safe", "unknown")
