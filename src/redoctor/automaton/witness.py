"""Witness (attack string) generation."""

from typing import Optional

from redoctor.automaton.complexity_analyzer import AmbiguityWitness
from redoctor.diagnostics.attack_pattern import AttackPattern
from redoctor.diagnostics.complexity import Complexity


class WitnessGenerator:
    """Generates attack strings from ambiguity witnesses."""

    def __init__(self, witness: AmbiguityWitness, complexity: Complexity):
        self.witness = witness
        self.complexity = complexity

    def generate_attack_pattern(self, repeat: int = 20) -> AttackPattern:
        """Generate an attack pattern from the witness.

        Args:
            repeat: Number of times to repeat the pump.

        Returns:
            AttackPattern with prefix, pump, and suffix.
        """
        prefix = "".join(chr(c) for c in self.witness.prefix)
        pump = "".join(chr(c) for c in self.witness.pump)
        suffix = "".join(chr(c) for c in self.witness.suffix)

        # Ensure pump is not empty
        if not pump:
            pump = "a"

        # Ensure suffix causes backtracking
        if not suffix:
            suffix = "!"

        return AttackPattern(
            prefix=prefix,
            pump=pump,
            suffix=suffix,
            repeat=repeat,
        )

    def generate_attack_string(self, repeat: int = 20) -> str:
        """Generate a complete attack string.

        Args:
            repeat: Number of times to repeat the pump.

        Returns:
            The attack string.
        """
        pattern = self.generate_attack_pattern(repeat)
        return pattern.build()


def generate_attack_from_witness(
    witness: Optional[AmbiguityWitness],
    complexity: Complexity,
    repeat: int = 20,
) -> Optional[AttackPattern]:
    """Generate an attack pattern from a witness.

    Args:
        witness: The ambiguity witness.
        complexity: The detected complexity.
        repeat: Number of pump repetitions.

    Returns:
        AttackPattern if witness is available, None otherwise.
    """
    if witness is None:
        return None

    generator = WitnessGenerator(witness, complexity)
    return generator.generate_attack_pattern(repeat)
