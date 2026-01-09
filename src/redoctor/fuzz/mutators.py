"""String mutation strategies for fuzzing."""

from abc import ABC, abstractmethod
from typing import List, Optional
import random

from redoctor.fuzz.fstring import FString


class Mutator(ABC):
    """Base class for string mutators."""

    @abstractmethod
    def mutate(self, s: FString) -> List[FString]:
        """Apply mutations to a string.

        Args:
            s: The string to mutate.

        Returns:
            List of mutated strings.
        """
        ...


class RandomMutator(Mutator):
    """Apply random mutations to strings."""

    def __init__(
        self,
        seed: Optional[int] = None,
        mutations_per_string: int = 10,
    ):
        self.rng = random.Random(seed)  # nosec B311 - not for crypto
        self.mutations_per_string = mutations_per_string

        # Characters useful for causing backtracking
        self.failure_chars = [ord("!"), ord("X"), ord("\x00"), ord("\n"), ord(" ")]

        # Common characters for pumping
        self.pump_chars = [ord("a"), ord("0"), ord(" "), ord(".")]

    def mutate(self, s: FString) -> List[FString]:
        """Apply random mutations."""
        mutations: List[FString] = []

        for _ in range(self.mutations_per_string):
            mutation = self._apply_random_mutation(s)
            if mutation:
                mutations.append(mutation)

        return mutations

    def _apply_random_mutation(self, s: FString) -> Optional[FString]:
        """Apply a single random mutation."""
        if len(s) == 0:
            # For empty strings, just add a character
            return s.append(self.rng.choice(self.pump_chars))

        mutation_type = self.rng.randint(0, 7)

        if mutation_type == 0:
            # Insert random character
            pos = self.rng.randint(0, len(s))
            c = self.rng.choice(self.pump_chars + self.failure_chars)
            return s.insert(pos, c)

        elif mutation_type == 1:
            # Delete random character
            if len(s) > 1:
                pos = self.rng.randint(0, len(s) - 1)
                return s.delete(pos)

        elif mutation_type == 2:
            # Replace random character
            pos = self.rng.randint(0, len(s) - 1)
            c = self.rng.choice(self.pump_chars + self.failure_chars)
            return s.replace(pos, c)

        elif mutation_type == 3:
            # Duplicate a portion
            if len(s) >= 2:
                start = self.rng.randint(0, len(s) - 1)
                end = self.rng.randint(start + 1, len(s))
                portion = s.chars[start:end]
                return FString(s.chars[:end] + portion + s.chars[end:])

        elif mutation_type == 4:
            # Append failure character
            c = self.rng.choice(self.failure_chars)
            return s.append(c)

        elif mutation_type == 5:
            # Repeat a portion
            if len(s) >= 1:
                start = self.rng.randint(0, len(s) - 1)
                end = self.rng.randint(start + 1, min(start + 5, len(s) + 1))
                portion = s.chars[start:end]
                repeat_count = self.rng.randint(2, 5)
                return FString(s.chars[:start] + portion * repeat_count + s.chars[end:])

        elif mutation_type == 6:
            # Swap two characters
            if len(s) >= 2:
                i = self.rng.randint(0, len(s) - 1)
                j = self.rng.randint(0, len(s) - 1)
                if i != j:
                    chars = list(s.chars)
                    chars[i], chars[j] = chars[j], chars[i]
                    return FString(chars)

        elif mutation_type == 7:
            # Extend pump if present
            if s.repeat_start < s.repeat_end:
                return s.expand_repeat(s.repeat_count + 1)

        return s.copy()


class PumpMutator(Mutator):
    """Focused mutations for pump detection."""

    def __init__(self, max_pump_length: int = 20):
        self.max_pump_length = max_pump_length

    def mutate(self, s: FString) -> List[FString]:
        """Generate pump-focused mutations."""
        mutations: List[FString] = []

        # Try different pump lengths
        for pump_len in range(1, min(self.max_pump_length, len(s) + 1)):
            for start in range(len(s) - pump_len + 1):
                end = start + pump_len
                pump = s.with_repeat(start, end, 1)

                # Generate increasing repetitions
                for count in [2, 5, 10, 20]:
                    mutations.append(pump.expand_repeat(count))

        # Add failure suffixes
        for m in list(mutations):
            mutations.append(m.append(ord("!")))
            mutations.append(m.append(ord("X")))

        return mutations


class CombinedMutator(Mutator):
    """Combine multiple mutation strategies."""

    def __init__(
        self,
        mutators: Optional[List[Mutator]] = None,
        seed: Optional[int] = None,
    ):
        if mutators is None:
            mutators = [
                RandomMutator(seed=seed),
                PumpMutator(),
            ]
        self.mutators = mutators

    def mutate(self, s: FString) -> List[FString]:
        """Apply all mutation strategies."""
        mutations: List[FString] = []
        for mutator in self.mutators:
            mutations.extend(mutator.mutate(s))
        return mutations
