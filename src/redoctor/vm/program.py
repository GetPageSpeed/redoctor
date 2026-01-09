"""Compiled regex program."""

from dataclasses import dataclass, field
from typing import List, Dict

from redoctor.vm.inst import Inst


@dataclass
class Program:
    """A compiled regex program.

    Attributes:
        instructions: List of VM instructions.
        num_captures: Number of capture groups.
        num_counters: Number of counters used.
        labels: Map from label names to instruction indices.
    """

    instructions: List[Inst] = field(default_factory=list)
    num_captures: int = 0
    num_counters: int = 0
    labels: Dict[str, int] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.instructions)

    def __getitem__(self, index: int) -> Inst:
        return self.instructions[index]

    def add(self, inst: Inst) -> int:
        """Add an instruction and return its index."""
        index = len(self.instructions)
        self.instructions.append(inst)
        if inst.label:
            self.labels[inst.label] = index
        return index

    def patch(self, index: int, target: int) -> None:
        """Patch a jump target."""
        inst = self.instructions[index]
        self.instructions[index] = Inst(
            op=inst.op,
            char=inst.char,
            target=target,
            target2=inst.target2,
            slot=inst.slot,
            counter=inst.counter,
            min=inst.min,
            max=inst.max,
            backref=inst.backref,
            label=inst.label,
        )

    def patch2(self, index: int, target2: int) -> None:
        """Patch the second jump target (for SPLIT)."""
        inst = self.instructions[index]
        self.instructions[index] = Inst(
            op=inst.op,
            char=inst.char,
            target=inst.target,
            target2=target2,
            slot=inst.slot,
            counter=inst.counter,
            min=inst.min,
            max=inst.max,
            backref=inst.backref,
            label=inst.label,
        )

    def dump(self) -> str:
        """Dump the program as a string."""
        lines = []
        for i, inst in enumerate(self.instructions):
            lines.append(f"{i:4d}: {inst}")
        return "\n".join(lines)
