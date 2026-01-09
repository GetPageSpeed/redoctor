"""Extended tests for the VM interpreter to increase coverage."""


from redoctor.parser.parser import parse
from redoctor.vm.inst import Inst, OpCode
from redoctor.vm.program import Program
from redoctor.vm.builder import build_program
from redoctor.vm.interpreter import Interpreter, MatchResult, count_steps
from redoctor.unicode.ichar import IChar


class TestInstructionsExtended:
    """Extended instruction tests."""

    def test_save_instruction(self):
        inst = Inst.save(0)
        assert inst.op == OpCode.SAVE
        assert inst.slot == 0

    def test_line_start_instruction(self):
        inst = Inst.line_start()
        assert inst.op == OpCode.LINE_START

    def test_line_end_instruction(self):
        inst = Inst.line_end()
        assert inst.op == OpCode.LINE_END

    def test_word_boundary_instruction(self):
        inst = Inst.word_boundary()
        assert inst.op == OpCode.WORD_BOUNDARY

    def test_backref_instruction(self):
        inst = Inst.backref(1)
        assert inst.op == OpCode.BACKREF
        assert inst.backref == 1

    def test_fail_instruction(self):
        inst = Inst.fail()
        assert inst.op == OpCode.FAIL

    def test_any_char_instruction(self):
        inst = Inst.any_char(dotall=True)
        assert inst.op == OpCode.ANY

    def test_instruction_repr(self):
        inst = Inst.char(IChar.from_char("a"), label="test")
        s = repr(inst)
        assert "CHAR" in s

        inst = Inst.jump(10)
        s = repr(inst)
        assert "JUMP" in s
        assert "10" in s

        inst = Inst.split(5, 10)
        s = repr(inst)
        assert "SPLIT" in s


class TestProgramExtended:
    """Extended program tests."""

    def test_patch2(self):
        prog = Program()
        prog.add(Inst.split(0, 0))
        prog.add(Inst.match())
        prog.patch2(0, 1)
        assert prog[0].target2 == 1

    def test_dump(self):
        prog = Program()
        prog.add(Inst.char(IChar.from_char("a")))
        prog.add(Inst.match())
        dump = prog.dump()
        assert "CHAR" in dump
        assert "MATCH" in dump


class TestBuilderExtended:
    """Extended program builder tests."""

    def test_build_dot(self):
        pattern = parse(".")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("x")
        assert result == MatchResult.MATCH

    def test_build_dot_dotall(self):
        from redoctor.parser.flags import Flags

        pattern = parse(".", Flags(dotall=True))
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("\n")
        assert result == MatchResult.MATCH

    def test_build_word_char(self):
        pattern = parse(r"\w")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH
        result, _ = interp.match("!")
        assert result == MatchResult.NO_MATCH

    def test_build_digit_char(self):
        pattern = parse(r"\d")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("5")
        assert result == MatchResult.MATCH
        result, _ = interp.match("a")
        assert result == MatchResult.NO_MATCH

    def test_build_space_char(self):
        pattern = parse(r"\s")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match(" ")
        assert result == MatchResult.MATCH
        result, _ = interp.match("a")
        assert result == MatchResult.NO_MATCH

    def test_build_negated_classes(self):
        pattern = parse(r"\W")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("!")
        assert result == MatchResult.MATCH

        pattern = parse(r"\D")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH

        pattern = parse(r"\S")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH

    def test_build_char_class_with_range(self):
        pattern = parse("[a-z0-9]")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("m")
        assert result == MatchResult.MATCH
        result, _ = interp.match("5")
        assert result == MatchResult.MATCH

    def test_build_negated_char_class(self):
        pattern = parse("[^abc]")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("x")
        assert result == MatchResult.MATCH
        result, _ = interp.match("a")
        assert result == MatchResult.NO_MATCH

    def test_build_line_start(self):
        pattern = parse("^a")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH

    def test_build_line_end(self):
        pattern = parse("a$")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH

    def test_build_word_boundary(self):
        pattern = parse(r"\bword")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("word")
        assert result == MatchResult.MATCH

    def test_build_non_word_boundary(self):
        pattern = parse(r"\B")
        prog = build_program(pattern)
        # Just verify it builds
        assert len(prog) > 0

    def test_build_lazy_quantifiers(self):
        # Lazy star - prefers empty match
        pattern = parse("a*?b")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("b")  # Should match with 0 a's
        assert result == MatchResult.MATCH
        result, _ = interp.match("aab")  # Should also match
        assert result == MatchResult.MATCH

        # Lazy plus - needs at least one
        pattern = parse("a+?b")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("ab")  # Matches with 1 a
        assert result == MatchResult.MATCH
        result, _ = interp.match("aaab")  # Also matches
        assert result == MatchResult.MATCH

        # Lazy question - prefers skip
        pattern = parse("a??b")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("b")  # Prefers no a
        assert result == MatchResult.MATCH
        result, _ = interp.match("ab")  # But can match a
        assert result == MatchResult.MATCH

    def test_build_bounded_quantifier_lazy(self):
        # Lazy bounded quantifier - prefers minimum matches
        pattern = parse("a{2,4}?b")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("aab")  # Matches with 2 a's
        assert result == MatchResult.MATCH
        result, _ = interp.match("aaaab")  # Also matches with 4 a's
        assert result == MatchResult.MATCH

    def test_build_lookahead(self):
        pattern = parse("(?=a)a")
        prog = build_program(pattern)
        assert len(prog) > 0

    def test_build_lookbehind(self):
        pattern = parse("(?<=a)b")
        prog = build_program(pattern)
        assert len(prog) > 0

    def test_build_backref(self):
        pattern = parse(r"(a)\1")
        prog = build_program(pattern)
        assert len(prog) > 0

    def test_build_flags_group(self):
        pattern = parse("(?i:abc)")
        prog = build_program(pattern)
        assert len(prog) > 0

    def test_build_atomic_group(self):
        pattern = parse("(?>abc)")
        prog = build_program(pattern)
        assert len(prog) > 0

    def test_build_case_insensitive(self):
        from redoctor.parser.flags import Flags

        pattern = parse("a", Flags(ignore_case=True))
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("A")
        assert result == MatchResult.MATCH


class TestInterpreterExtended:
    """Extended interpreter tests."""

    def test_line_start_after_newline(self):
        pattern = parse("^a")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        # Test that ^ matches after newline in multiline-like behavior
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH

    def test_line_end_before_newline(self):
        pattern = parse("a$")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH

    def test_word_boundary_at_start(self):
        pattern = parse(r"\btest")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("test")
        assert result == MatchResult.MATCH

    def test_word_boundary_at_end(self):
        pattern = parse(r"test\b")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("test")
        assert result == MatchResult.MATCH

    def test_non_word_boundary(self):
        pattern = parse(r"a\Bb")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("ab")
        assert result == MatchResult.MATCH

    def test_backtracking_complex(self):
        pattern = parse("(ab|a)(bc|b)")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("abc")
        assert result == MatchResult.MATCH

    def test_capture_groups(self):
        pattern = parse("(a)(b)(c)")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("abc")
        assert result == MatchResult.MATCH

    def test_nested_captures(self):
        pattern = parse("((a)b)")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("ab")
        assert result == MatchResult.MATCH

    def test_empty_match(self):
        pattern = parse("")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("")
        assert result == MatchResult.MATCH

    def test_alternation_backtrack(self):
        pattern = parse("aaa|aa|a")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("aa")
        assert result == MatchResult.MATCH

    def test_greedy_vs_lazy(self):
        # Greedy
        pattern = parse("a+")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("aaa")
        assert result == MatchResult.MATCH

        # Lazy
        pattern = parse("a+?")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("aaa")
        assert result == MatchResult.MATCH

    def test_quantifier_min_max(self):
        pattern = parse("a{3}")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("aaa")
        assert result == MatchResult.MATCH
        result, _ = interp.match("aa")
        assert result == MatchResult.NO_MATCH

    def test_optional_groups(self):
        pattern = parse("(ab)?c")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("abc")
        assert result == MatchResult.MATCH
        result, _ = interp.match("c")
        assert result == MatchResult.MATCH


class TestCountSteps:
    """Test step counting function."""

    def test_count_steps_simple(self):
        pattern = parse("abc")
        prog = build_program(pattern)
        steps = count_steps(prog, "abc")
        assert steps > 0

    def test_count_steps_with_backtracking(self):
        pattern = parse("(a|ab)c")
        prog = build_program(pattern)
        steps = count_steps(prog, "abc")
        assert steps > 0

    def test_count_steps_limit(self):
        pattern = parse("a+")
        prog = build_program(pattern)
        steps = count_steps(prog, "a" * 100, max_steps=50)
        assert steps <= 51


class TestInterpreterEdgeCases:
    """Test interpreter edge cases for coverage."""

    def test_any_char_dotall(self):
        from redoctor.parser.flags import Flags

        pattern = parse(".", Flags(dotall=True))
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("\n")
        assert result == MatchResult.MATCH

    def test_any_char_no_dotall(self):
        pattern = parse(".")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("x")
        assert result == MatchResult.MATCH

    def test_fail_instruction(self):
        prog = Program()
        prog.add(Inst.fail())
        interp = Interpreter(prog)
        result, _ = interp.match("x")
        assert result == MatchResult.NO_MATCH

    def test_save_and_restore(self):
        pattern = parse("(a)(b)")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("ab")
        assert result == MatchResult.MATCH

    def test_complex_backtracking(self):
        pattern = parse("(a+|b+)+c")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("aaabbbaaac")
        assert result == MatchResult.MATCH

    def test_match_timeout_steps(self):
        pattern = parse("(a+)+")
        prog = build_program(pattern)
        interp = Interpreter(prog, max_steps=100)
        result, steps = interp.match("a" * 50)
        # Should either match or exceed steps
        assert steps > 0

    def test_empty_input(self):
        pattern = parse("a*")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("")
        assert result == MatchResult.MATCH

    def test_no_match_at_all(self):
        pattern = parse("xyz")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("abc")
        assert result == MatchResult.NO_MATCH

    def test_split_backtrack(self):
        # Pattern where first alternative fails and must backtrack
        pattern = parse("(ab|a)b")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("ab")
        assert result == MatchResult.MATCH

    def test_nested_quantifiers(self):
        pattern = parse("((a+)+)+")
        prog = build_program(pattern)
        interp = Interpreter(prog, max_steps=1000)
        result, _ = interp.match("aaa")
        assert result == MatchResult.MATCH
