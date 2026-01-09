"""Tests for the VM interpreter."""


from redoctor.parser.parser import parse
from redoctor.vm.inst import Inst, OpCode
from redoctor.vm.program import Program
from redoctor.vm.builder import build_program
from redoctor.vm.interpreter import Interpreter, MatchResult, count_steps


class TestInstructions:
    """Test VM instructions."""

    def test_char_instruction(self):
        from redoctor.unicode.ichar import IChar

        inst = Inst.char(IChar.from_char("a"))
        assert inst.op == OpCode.CHAR

    def test_jump_instruction(self):
        inst = Inst.jump(10)
        assert inst.op == OpCode.JUMP
        assert inst.target == 10

    def test_split_instruction(self):
        inst = Inst.split(5, 10)
        assert inst.op == OpCode.SPLIT
        assert inst.target == 5
        assert inst.target2 == 10

    def test_match_instruction(self):
        inst = Inst.match()
        assert inst.op == OpCode.MATCH


class TestProgram:
    """Test compiled programs."""

    def test_empty_program(self):
        prog = Program()
        assert len(prog) == 0

    def test_add_instruction(self):
        prog = Program()
        idx = prog.add(Inst.match())
        assert idx == 0
        assert len(prog) == 1

    def test_patch(self):
        prog = Program()
        prog.add(Inst.jump(0))
        prog.add(Inst.match())
        prog.patch(0, 1)
        assert prog[0].target == 1


class TestProgramBuilder:
    """Test program building from patterns."""

    def test_build_char(self):
        pattern = parse("a")
        prog = build_program(pattern)
        assert len(prog) > 0

    def test_build_sequence(self):
        pattern = parse("abc")
        prog = build_program(pattern)
        assert len(prog) >= 4  # 3 chars + match

    def test_build_star(self):
        pattern = parse("a*")
        prog = build_program(pattern)
        assert len(prog) >= 2  # split, char, jump, match

    def test_build_plus(self):
        pattern = parse("a+")
        prog = build_program(pattern)
        assert len(prog) >= 2

    def test_build_capture(self):
        pattern = parse("(a)")
        prog = build_program(pattern)
        assert prog.num_captures >= 1


class TestInterpreter:
    """Test the VM interpreter."""

    def test_match_char(self):
        pattern = parse("a")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, steps = interp.match("a")
        assert result == MatchResult.MATCH

    def test_no_match_char(self):
        pattern = parse("a")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("b")
        assert result == MatchResult.NO_MATCH

    def test_match_sequence(self):
        pattern = parse("abc")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("abc")
        assert result == MatchResult.MATCH
        result, _ = interp.match("ab")
        assert result == MatchResult.NO_MATCH

    def test_match_star(self):
        pattern = parse("a*")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("")
        assert result == MatchResult.MATCH
        result, _ = interp.match("aaa")
        assert result == MatchResult.MATCH

    def test_match_plus(self):
        pattern = parse("a+")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("")
        assert result == MatchResult.NO_MATCH
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH

    def test_match_disjunction(self):
        pattern = parse("a|b")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH
        result, _ = interp.match("b")
        assert result == MatchResult.MATCH
        result, _ = interp.match("c")
        assert result == MatchResult.NO_MATCH

    def test_step_counting(self):
        pattern = parse("a+")
        prog = build_program(pattern)
        steps = count_steps(prog, "aaaa")
        assert steps > 0

    def test_timeout(self):
        # Create a pattern that will cause many steps
        pattern = parse("(a+)+")
        prog = build_program(pattern)
        interp = Interpreter(prog, max_steps=100)
        result, steps = interp.match("aaaaaaaaaaX")
        # May timeout or complete depending on implementation
        assert steps <= 101  # max_steps + 1


class TestComplexPatterns:
    """Test complex pattern matching."""

    def test_nested_groups(self):
        pattern = parse("((a)(b))")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("ab")
        assert result == MatchResult.MATCH

    def test_quantifier(self):
        pattern = parse("a{2,4}")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.NO_MATCH
        result, _ = interp.match("aa")
        assert result == MatchResult.MATCH
        result, _ = interp.match("aaaa")
        assert result == MatchResult.MATCH
        # Note: "aaaaa" matches because VM does prefix match (like re.match)
        # It matches the first 4 'a's and succeeds
        result, _ = interp.match("aaaaa")
        assert result == MatchResult.MATCH  # Prefix match succeeds

    def test_anchors(self):
        pattern = parse("^a$")
        prog = build_program(pattern)
        interp = Interpreter(prog)
        result, _ = interp.match("a")
        assert result == MatchResult.MATCH
