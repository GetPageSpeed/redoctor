"""Automaton module for static analysis."""

from redoctor.automaton.eps_nfa import EpsNFA, State, Transition
from redoctor.automaton.eps_nfa_builder import build_eps_nfa
from redoctor.automaton.ordered_nfa import OrderedNFA
from redoctor.automaton.complexity_analyzer import ComplexityAnalyzer
from redoctor.automaton.witness import WitnessGenerator
from redoctor.automaton.checker import AutomatonChecker

__all__ = [
    "EpsNFA",
    "State",
    "Transition",
    "build_eps_nfa",
    "OrderedNFA",
    "ComplexityAnalyzer",
    "WitnessGenerator",
    "AutomatonChecker",
]
