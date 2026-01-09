"""Seed generation for fuzzing."""

from abc import ABC, abstractmethod
from typing import List

from redoctor.fuzz.fstring import FString
from redoctor.parser.ast import (
    Node,
    Pattern,
    Disjunction,
    Sequence,
    Empty,
    Capture,
    NamedCapture,
    NonCapture,
    FlagsGroup,
    AtomicGroup,
    Star,
    Plus,
    Question,
    Quantifier,
    Char,
    Dot,
    CharClass,
    CharClassRange,
    WordChar,
    DigitChar,
    SpaceChar,
    LookAhead,
    NegLookAhead,
    LookBehind,
    NegLookBehind,
    Backref,
    NamedBackref,
)


class Seeder(ABC):
    """Base class for seed generators."""

    @abstractmethod
    def generate(self, pattern: Pattern) -> List[FString]:
        """Generate seed strings for fuzzing.

        Args:
            pattern: The parsed regex pattern.

        Returns:
            List of seed strings.
        """
        ...


class StaticSeeder(Seeder):
    """Generate seeds by analyzing the regex structure."""

    def __init__(self, max_seeds: int = 100):
        self.max_seeds = max_seeds

    def generate(self, pattern: Pattern) -> List[FString]:
        """Generate seeds from the pattern."""
        seeds: List[FString] = []

        # Generate matching strings
        matching = self._generate_matching(pattern.node)
        seeds.extend(matching[: self.max_seeds // 2])

        # Generate near-miss strings (for triggering backtracking)
        for seed in matching[:10]:
            # Add failure suffixes
            seeds.append(seed.append(ord("!")))
            seeds.append(seed.append(ord("X")))
            seeds.append(seed.append(ord("\x00")))

        # Generate pump candidates
        pumps = self._find_pump_candidates(pattern.node)
        for pump in pumps[:20]:
            # Create strings with repeated pump
            for n in [5, 10, 20]:
                expanded = FString([ord(c) for c in pump * n])
                seeds.append(expanded.append(ord("!")))

        return seeds[: self.max_seeds]

    def _generate_matching(self, node: Node) -> List[FString]:
        """Generate strings that match the pattern."""
        if isinstance(node, Empty):
            return [FString.empty()]

        if isinstance(node, Char):
            return [FString([node.char])]

        if isinstance(node, Dot):
            return [FString([ord("a")])]

        if isinstance(node, (WordChar, DigitChar, SpaceChar)):
            if isinstance(node, WordChar):
                return [FString([ord("a" if not node.negated else "!")])]
            if isinstance(node, DigitChar):
                return [FString([ord("0" if not node.negated else "a")])]
            if isinstance(node, SpaceChar):
                return [FString([ord(" " if not node.negated else "a")])]

        if isinstance(node, CharClass):
            if node.items:
                first = node.items[0]
                if isinstance(first, Char):
                    return [FString([first.char])]
                if isinstance(first, CharClassRange):
                    return [FString([first.start])]
            return [FString([ord("a")])]

        if isinstance(node, Disjunction):
            results = []
            for alt in node.alternatives:
                results.extend(self._generate_matching(alt))
            return results

        if isinstance(node, Sequence):
            if not node.nodes:
                return [FString.empty()]
            result = [FString.empty()]
            for child in node.nodes:
                child_matches = self._generate_matching(child)
                new_result = []
                for r in result[:5]:  # Limit combinations
                    for cm in child_matches[:5]:
                        new_result.append(r.concat(cm))
                result = new_result
            return result

        if isinstance(
            node, (Capture, NamedCapture, NonCapture, FlagsGroup, AtomicGroup)
        ):
            child = getattr(node, "child", None)
            if child:
                return self._generate_matching(child)
            return [FString.empty()]

        if isinstance(node, Star):
            child_matches = self._generate_matching(node.child)
            result = [FString.empty()]
            for cm in child_matches[:3]:
                result.append(cm)
                result.append(cm.concat(cm))
            return result

        if isinstance(node, Plus):
            return self._generate_matching(node.child)

        if isinstance(node, Question):
            result = [FString.empty()]
            result.extend(self._generate_matching(node.child))
            return result

        if isinstance(node, Quantifier):
            child_matches = self._generate_matching(node.child)
            result = []
            for cm in child_matches[:3]:
                repeated = FString.empty()
                for _ in range(node.min):
                    repeated = repeated.concat(cm)
                result.append(repeated)
            return result if result else [FString.empty()]

        if isinstance(node, (LookAhead, NegLookAhead, LookBehind, NegLookBehind)):
            return [FString.empty()]

        if isinstance(node, (Backref, NamedBackref)):
            return [FString.empty()]

        return [FString.empty()]

    def _find_pump_candidates(self, node: Node) -> List[str]:
        """Find potential pump strings (repeated patterns)."""
        candidates: List[str] = []

        for child in node.walk():
            if isinstance(child, (Star, Plus)):
                inner_matches = self._generate_matching(child.child)
                for m in inner_matches[:5]:
                    if len(m) > 0:
                        candidates.append(str(m))

            if isinstance(child, Quantifier) and (
                child.max is None or child.max > child.min
            ):
                inner_matches = self._generate_matching(child.child)
                for m in inner_matches[:5]:
                    if len(m) > 0:
                        candidates.append(str(m))

        return candidates


class DynamicSeeder(Seeder):
    """Generate seeds dynamically based on execution feedback."""

    def __init__(self, max_seeds: int = 100):
        self.max_seeds = max_seeds
        self.static_seeder = StaticSeeder(max_seeds)

    def generate(self, pattern: Pattern) -> List[FString]:
        """Generate initial seeds (uses static seeder as base)."""
        return self.static_seeder.generate(pattern)

    def refine(self, seed: FString, steps: int, target_steps: int) -> List[FString]:
        """Refine a seed based on execution feedback.

        Args:
            seed: The current seed.
            steps: Steps taken with this seed.
            target_steps: Target step count for detecting vulnerability.

        Returns:
            List of refined seeds.
        """
        refined: List[FString] = []

        # If we're getting many steps, try expanding repeats
        if steps > target_steps * 0.5:
            # Identify potential pump regions
            for i in range(len(seed)):
                for j in range(i + 1, min(i + 10, len(seed))):
                    # Try marking [i:j] as the pump
                    pump = seed.with_repeat(i, j, 1)
                    refined.append(pump.expand_repeat(5))
                    refined.append(pump.expand_repeat(10))

        return refined[:20]
