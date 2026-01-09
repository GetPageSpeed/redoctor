"""Pytest fixtures and configuration."""

import pytest

from redoctor.config import Config
from redoctor.parser.flags import Flags


@pytest.fixture
def quick_config():
    """Quick configuration for tests."""
    return Config.quick()


@pytest.fixture
def default_flags():
    """Default flags for tests."""
    return Flags()


# Known vulnerable patterns for testing
VULNERABLE_PATTERNS = [
    r"^(a+)+$",  # Classic exponential
    r"^(a|a)+$",  # Alternation exponential
    r"^(a+)+b$",  # Exponential with suffix
    r"^([a-zA-Z]+)*$",  # Nested quantifier
    r"^(.*a){10}$",  # Polynomial
    r"^(\w+\s*)+$",  # Word + space
    r"^(a*)*$",  # Nested star
]

SAFE_PATTERNS = [
    r"^[a-z]+$",  # Simple character class
    r"^\d{4}-\d{2}-\d{2}$",  # Date format
    r"^hello$",  # Literal
    r"^[a-zA-Z0-9]+$",  # Alphanumeric
    r"^.{1,100}$",  # Bounded dot
]


@pytest.fixture
def vulnerable_patterns():
    """List of known vulnerable patterns."""
    return VULNERABLE_PATTERNS


@pytest.fixture
def safe_patterns():
    """List of known safe patterns."""
    return SAFE_PATTERNS
