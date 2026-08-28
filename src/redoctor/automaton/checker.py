"""Automaton-based ReDoS checker."""

from redoctor.parser.parser import parse, Pattern
from redoctor.parser.flags import Flags
from redoctor.parser.ast import (
    has_backreferences,
    has_end_anchor,
    requires_continuation,
)
from redoctor.automaton.eps_nfa_builder import build_eps_nfa
from redoctor.automaton.complexity_analyzer import ComplexityAnalyzer, MatchMode
from redoctor.automaton.witness import generate_attack_from_witness
from redoctor.diagnostics.diagnostics import Diagnostics
from redoctor.diagnostics.hotspot import Hotspot
from redoctor.config import Config
from redoctor.exceptions import ParseError


class AutomatonChecker:
    """Checker using automata-theoretic static analysis.

    This checker works best for regular expressions without
    backreferences or lookaround assertions.
    """

    def __init__(self, config: Config = None):
        self.config = config or Config.default()

    def check(self, pattern: str, flags: Flags = None) -> Diagnostics:
        """Check a regex pattern for ReDoS vulnerabilities.

        Args:
            pattern: The regex pattern string.
            flags: Optional regex flags.

        Returns:
            Diagnostics result.
        """
        try:
            parsed = parse(pattern, flags)
            return self.check_pattern(parsed)
        except ParseError as e:
            return Diagnostics.from_error(pattern, str(e))

    def check_pattern(self, pattern: Pattern) -> Diagnostics:
        """Check a parsed pattern for ReDoS vulnerabilities.

        Args:
            pattern: The parsed Pattern AST.

        Returns:
            Diagnostics result.
        """
        # Check if pattern has features not supported by automaton checker
        if has_backreferences(pattern.node):
            return Diagnostics.unknown(
                pattern.source,
                checker="automaton",
                message="Pattern contains backreferences; use fuzz checker.",
            )

        # Build NFA
        try:
            eps_nfa = build_eps_nfa(pattern)
        except Exception as e:
            return Diagnostics.from_error(
                pattern.source, f"NFA construction failed: {e}"
            )

        # Check NFA size
        if eps_nfa.size() > self.config.max_nfa_size:
            return Diagnostics.unknown(
                pattern.source,
                checker="automaton",
                message=f"NFA too large ({eps_nfa.size()} states); use fuzz checker.",
            )

        # Determine match mode and anchor status
        # Convert config match_mode to internal MatchMode enum
        from redoctor.config import MatchMode as ConfigMatchMode

        if self.config.match_mode == ConfigMatchMode.FULL:
            match_mode = MatchMode.FULL
        elif self.config.match_mode == ConfigMatchMode.PARTIAL:
            match_mode = MatchMode.PARTIAL
        else:
            match_mode = MatchMode.AUTO

        # Check for end anchor and continuation requirements in the pattern
        pattern_has_end_anchor = has_end_anchor(pattern.node)
        pattern_requires_continuation = requires_continuation(pattern.node)

        # Analyze complexity
        analyzer = ComplexityAnalyzer(
            eps_nfa,
            match_mode=match_mode,
            has_end_anchor=pattern_has_end_anchor,
            requires_continuation=pattern_requires_continuation,
        )
        complexity, witness = analyzer.analyze()

        if complexity.is_safe:
            return Diagnostics.safe(pattern.source, checker="automaton")

        # Generate attack pattern
        attack_pattern = generate_attack_from_witness(
            witness,
            complexity,
            repeat=self.config.attack_limit,
        )

        # Generate hotspot
        hotspot = None
        if witness:
            # Approximate hotspot from witness states
            hotspot = Hotspot(
                start=0,
                end=len(pattern.source),
                pattern=pattern.source,
            )

        return Diagnostics.vulnerable(
            source=pattern.source,
            complexity=complexity,
            attack_pattern=attack_pattern,
            hotspot=hotspot,
            checker="automaton",
        )

    def can_analyze(self, pattern: Pattern) -> bool:
        """Check if this checker can analyze the pattern.

        Returns False for patterns with backreferences or complex lookaround.
        """
        if has_backreferences(pattern.node):
            return False
        # Lookaround is partially supported
        return True


def check_with_automaton(
    pattern: str, flags: Flags = None, config: Config = None
) -> Diagnostics:
    """Convenience function to check a pattern with automaton checker.

    Args:
        pattern: The regex pattern.
        flags: Optional regex flags.
        config: Optional configuration.

    Returns:
        Diagnostics result.
    """
    checker = AutomatonChecker(config)
    return checker.check(pattern, flags)
