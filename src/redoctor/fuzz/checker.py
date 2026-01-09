"""Fuzz-based ReDoS checker."""

from dataclasses import dataclass
from typing import List, Optional, Tuple
import time

from redoctor.parser.parser import parse, Pattern
from redoctor.parser.flags import Flags
from redoctor.vm.builder import build_program
from redoctor.vm.interpreter import Interpreter, MatchResult, count_steps
from redoctor.fuzz.fstring import FString
from redoctor.fuzz.seeder import StaticSeeder
from redoctor.fuzz.mutators import CombinedMutator
from redoctor.diagnostics.diagnostics import Diagnostics
from redoctor.diagnostics.complexity import Complexity
from redoctor.diagnostics.attack_pattern import AttackPattern
from redoctor.config import Config
from redoctor.exceptions import ParseError


@dataclass
class FuzzResult:
    """Result of fuzzing a single string.

    Attributes:
        string: The fuzzed string.
        steps: Number of steps taken.
        matched: Whether the string matched.
    """

    string: FString
    steps: int
    matched: bool


class FuzzChecker:
    """Checker using fuzzing and VM step counting.

    This checker works well for all regex patterns, including
    those with backreferences and lookaround.
    """

    def __init__(self, config: Config = None):
        self.config = config or Config.default()

        # Thresholds for detecting vulnerability
        self.linear_threshold = 100  # Steps per character for linear
        self.polynomial_threshold = 10000  # Base steps for polynomial detection
        self.exponential_threshold = 100000  # Base steps for exponential detection

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
        try:
            program = build_program(pattern)
        except Exception as e:
            return Diagnostics.from_error(pattern.source, f"Compilation failed: {e}")

        # Generate seeds
        seeder = StaticSeeder(max_seeds=50)
        seeds = seeder.generate(pattern)

        # Add some basic seeds if none generated
        if not seeds:
            seeds = [
                FString.from_str("a"),
                FString.from_str("aa"),
                FString.from_str("aaa"),
                FString.from_str("!"),
            ]

        # Mutator for evolving strings
        mutator = CombinedMutator(seed=self.config.random_seed)

        # Track best candidates
        best_result: Optional[Tuple[FString, int]] = None
        start_time = time.time()

        # Fuzz loop
        queue = list(seeds)
        iterations = 0
        max_iterations = self.config.max_iterations

        while queue and iterations < max_iterations:
            if time.time() - start_time > self.config.timeout:
                break

            iterations += 1
            candidate = queue.pop(0)

            # Skip if too long
            if len(candidate) > self.config.max_attack_length:
                continue

            # Run the candidate
            result = self._run_candidate(program, candidate)

            # Check for vulnerability
            if result.steps > self.exponential_threshold:
                # Found exponential behavior
                attack_pattern = self._extract_attack_pattern(candidate)
                return Diagnostics.vulnerable(
                    source=pattern.source,
                    complexity=Complexity.exponential(),
                    attack_pattern=attack_pattern,
                    checker="fuzz",
                )

            # Check for polynomial behavior
            if result.steps > self.polynomial_threshold:
                # Check if it's actually polynomial by comparing step growth
                complexity = self._estimate_complexity(program, candidate)
                if complexity.is_vulnerable:
                    attack_pattern = self._extract_attack_pattern(candidate)
                    return Diagnostics.vulnerable(
                        source=pattern.source,
                        complexity=complexity,
                        attack_pattern=attack_pattern,
                        checker="fuzz",
                    )

            # Track best result
            if best_result is None or result.steps > best_result[1]:
                best_result = (candidate, result.steps)

            # Add mutations to queue
            if result.steps > self.linear_threshold * len(candidate):
                # Promising candidate - mutate it
                mutations = mutator.mutate(candidate)
                queue.extend(mutations[:20])

        # No clear vulnerability found
        if best_result and best_result[1] > self.polynomial_threshold * 0.5:
            # Suspicious but not conclusive
            return Diagnostics.unknown(
                pattern.source,
                checker="fuzz",
                message=f"Suspicious step count ({best_result[1]}) but inconclusive.",
            )

        return Diagnostics.safe(pattern.source, checker="fuzz")

    def _run_candidate(self, program, candidate: FString) -> FuzzResult:
        """Run a single candidate string."""
        interpreter = Interpreter(program, max_steps=self.exponential_threshold * 2)
        result, steps = interpreter.match(str(candidate))
        return FuzzResult(
            string=candidate,
            steps=steps,
            matched=(result == MatchResult.MATCH),
        )

    def _estimate_complexity(self, program, candidate: FString) -> Complexity:
        """Estimate complexity by measuring step growth."""
        # Find the pump portion
        if candidate.repeat_start < candidate.repeat_end:
            pump = str(candidate.pump)
            prefix = str(candidate.prefix)
            suffix = str(candidate.suffix)
        else:
            # Try to identify pump heuristically
            pump = str(candidate)[: min(5, len(candidate))]
            prefix = ""
            suffix = "!"

        if not pump:
            return Complexity.safe()

        # Measure steps for increasing pump counts
        measurements: List[Tuple[int, int]] = []
        for n in [5, 10, 15, 20]:
            test_str = prefix + pump * n + suffix
            if len(test_str) > self.config.max_attack_length:
                break
            steps = count_steps(program, test_str, self.exponential_threshold * 2)
            measurements.append((n, steps))

        if len(measurements) < 2:
            return Complexity.safe()

        # Analyze growth pattern
        # Exponential: steps roughly doubles for each increment
        # Polynomial: steps grows as n^k
        # Linear: steps grows as n

        # Simple heuristic: check ratio of last to first
        first_n, first_steps = measurements[0]
        last_n, last_steps = measurements[-1]

        if first_steps == 0:
            return Complexity.safe()

        ratio = last_steps / first_steps
        n_ratio = last_n / first_n

        if ratio > n_ratio**3:
            return Complexity.exponential()
        elif ratio > n_ratio**2:
            return Complexity.polynomial(3)
        elif ratio > n_ratio**1.5:
            return Complexity.polynomial(2)
        else:
            return Complexity.safe()

    def _extract_attack_pattern(self, candidate: FString) -> AttackPattern:
        """Extract attack pattern from a successful candidate."""
        if candidate.repeat_start < candidate.repeat_end:
            prefix = "".join(chr(c) for c in candidate.chars[: candidate.repeat_start])
            pump = "".join(
                chr(c)
                for c in candidate.chars[candidate.repeat_start : candidate.repeat_end]
            )
            suffix = "".join(chr(c) for c in candidate.chars[candidate.repeat_end :])
        else:
            # Heuristic: assume last character is suffix, rest is pump
            s = str(candidate)
            if len(s) > 1:
                prefix = ""
                pump = s[:-1] if len(s) > 1 else s
                suffix = s[-1] if len(s) > 0 else "!"
            else:
                prefix = ""
                pump = "a"
                suffix = "!"

        return AttackPattern(
            prefix=prefix,
            pump=pump if pump else "a",
            suffix=suffix if suffix else "!",
        )


def check_with_fuzz(
    pattern: str, flags: Flags = None, config: Config = None
) -> Diagnostics:
    """Convenience function to check a pattern with fuzz checker.

    Args:
        pattern: The regex pattern.
        flags: Optional regex flags.
        config: Optional configuration.

    Returns:
        Diagnostics result.
    """
    checker = FuzzChecker(config)
    return checker.check(pattern, flags)
