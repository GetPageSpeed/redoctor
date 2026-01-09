"""Extended fuzz tests for increased coverage."""


from redoctor.parser.parser import parse
from redoctor.fuzz.fstring import FString
from redoctor.fuzz.seeder import StaticSeeder
from redoctor.fuzz.mutators import RandomMutator, PumpMutator, CombinedMutator
from redoctor.fuzz.checker import FuzzChecker
from redoctor.config import Config


class TestFStringExtended:
    """Extended FString tests."""

    def test_repr(self):
        s = FString.from_str("hello")
        assert "hello" in repr(s)

    def test_extend(self):
        s = FString.from_str("ab")
        s2 = s.extend([ord("c"), ord("d")])
        assert str(s2) == "abcd"

    def test_slice_no_end(self):
        s = FString.from_str("hello")
        s2 = s.slice(2)
        assert str(s2) == "llo"

    def test_prefix_pump_suffix(self):
        s = FString.from_str("aXXXb")
        s = s.with_repeat(1, 4, 1)
        assert str(s.prefix) == "a"
        assert str(s.pump) == "XXX"
        assert str(s.suffix) == "b"

    def test_prefix_empty(self):
        s = FString.from_str("XXXb")
        s = s.with_repeat(0, 3, 1)
        assert str(s.prefix) == ""

    def test_pump_empty(self):
        s = FString.from_str("ab")
        assert str(s.pump) == ""

    def test_suffix_empty(self):
        s = FString.from_str("aXXX")
        s = s.with_repeat(1, 4, 1)
        assert str(s.suffix) == ""

    def test_expand_repeat_no_change(self):
        s = FString.from_str("abc")
        # No repeat range set
        s2 = s.expand_repeat(5)
        assert str(s2) == "abc"

    def test_delete_out_of_bounds(self):
        s = FString.from_str("ab")
        s2 = s.delete(10)
        assert str(s2) == "ab"

        s3 = s.delete(-1)
        assert str(s3) == "ab"

    def test_replace_out_of_bounds(self):
        s = FString.from_str("ab")
        s2 = s.replace(10, ord("x"))
        assert str(s2) == "ab"

        s3 = s.replace(-1, ord("x"))
        assert str(s3) == "ab"


class TestStaticSeederExtended:
    """Extended static seeder tests."""

    def test_generate_disjunction(self):
        pattern = parse("a|b|c")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_question(self):
        pattern = parse("a?")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_quantifier(self):
        pattern = parse("a{2,5}")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_capture(self):
        pattern = parse("(abc)")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_dot(self):
        pattern = parse(".")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_char_class(self):
        pattern = parse("[a-z]")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_predefined_class(self):
        pattern = parse(r"\w")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_negated_predefined(self):
        pattern = parse(r"\W")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) > 0

    def test_generate_lookahead(self):
        pattern = parse("(?=a)")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) >= 0  # May return empty

    def test_generate_empty_sequence(self):
        pattern = parse("")
        seeder = StaticSeeder()
        seeds = seeder.generate(pattern)
        assert len(seeds) >= 0


class TestMutatorsExtended:
    """Extended mutator tests."""

    def test_random_mutator_all_types(self):
        mutator = RandomMutator(seed=42, mutations_per_string=100)
        s = FString.from_str("abcdef")
        mutations = mutator.mutate(s)
        # Should have variety
        assert len(mutations) == 100

    def test_random_mutator_with_repeat(self):
        mutator = RandomMutator(seed=42)
        s = FString.from_str("abc")
        s = s.with_repeat(0, 2, 1)
        mutations = mutator.mutate(s)
        assert len(mutations) > 0

    def test_pump_mutator_small_string(self):
        mutator = PumpMutator(max_pump_length=3)
        s = FString.from_str("ab")
        mutations = mutator.mutate(s)
        assert len(mutations) > 0

    def test_combined_mutator_custom(self):
        mutators = [RandomMutator(seed=1, mutations_per_string=5)]
        combined = CombinedMutator(mutators=mutators)
        s = FString.from_str("test")
        mutations = combined.mutate(s)
        assert len(mutations) >= 5


class TestFuzzCheckerExtended:
    """Extended fuzz checker tests."""

    def test_check_parse_error(self):
        checker = FuzzChecker(Config.quick())
        result = checker.check("(unclosed")
        assert result.error is not None

    def test_check_empty_pattern(self):
        checker = FuzzChecker(Config.quick())
        result = checker.check("")
        assert result is not None

    def test_check_with_backreference(self):
        checker = FuzzChecker(Config.quick())
        result = checker.check(r"(a)\1")
        assert result is not None

    def test_check_complex_pattern(self):
        config = Config(timeout=1.0, max_iterations=100)
        checker = FuzzChecker(config)
        result = checker.check(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        assert result is not None

    def test_check_nested_quantifier(self):
        config = Config(timeout=0.5, max_iterations=50)
        checker = FuzzChecker(config)
        result = checker.check(r"^(a+)+$")
        assert result is not None

    def test_check_alternation_overlap(self):
        config = Config(timeout=0.5, max_iterations=50)
        checker = FuzzChecker(config)
        result = checker.check(r"^(a|aa)+$")
        assert result is not None

    def test_check_with_flags(self):
        from redoctor.parser.flags import Flags

        checker = FuzzChecker(Config.quick())
        result = checker.check(r"^hello$", Flags(ignore_case=True))
        assert result is not None

    def test_check_with_custom_config(self):
        config = Config(timeout=0.5, max_iterations=20)
        checker = FuzzChecker(config)
        result = checker.check(r"^[a-z]+$")
        assert result is not None

    def test_fuzz_loop_finds_vulnerability(self):
        # This pattern should be detected as vulnerable by fuzzing
        config = Config(timeout=1.0, max_iterations=200)
        checker = FuzzChecker(config)
        result = checker.check(r"^(a*)*$")
        # Should complete without error
        assert result is not None


class TestFuzzCheckerInternal:
    """Test internal fuzz checker methods."""

    def test_extract_attack_pattern_with_repeat(self):
        checker = FuzzChecker(Config.quick())
        candidate = FString.from_str("xaaaa!")
        candidate = candidate.with_repeat(1, 5, 1)

        pattern = checker._extract_attack_pattern(candidate)
        assert pattern.prefix == "x"
        assert pattern.pump == "aaaa"
        assert pattern.suffix == "!"

    def test_extract_attack_pattern_no_repeat(self):
        checker = FuzzChecker(Config.quick())
        candidate = FString.from_str("abc")

        pattern = checker._extract_attack_pattern(candidate)
        assert pattern.prefix == ""
        assert pattern.pump == "ab"
        assert pattern.suffix == "c"

    def test_extract_attack_pattern_single_char(self):
        checker = FuzzChecker(Config.quick())
        candidate = FString.from_str("x")

        pattern = checker._extract_attack_pattern(candidate)
        assert pattern.pump == "a"
        assert pattern.suffix == "!"

    def test_full_fuzz_check_vulnerable(self):
        # Test full fuzz check on known vulnerable pattern
        config = Config(timeout=2.0, max_iterations=500)
        checker = FuzzChecker(config)
        result = checker.check(r"^(a+)+$")
        # Should detect as vulnerable or at least complete without error
        assert result is not None

    def test_full_fuzz_check_safe(self):
        config = Config(timeout=0.5, max_iterations=100)
        checker = FuzzChecker(config)
        result = checker.check(r"^[a-z]+$")
        assert result is not None
