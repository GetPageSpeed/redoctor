"""Main ReDoS checker combining all detection methods."""


from redoctor.parser.parser import parse, Pattern
from redoctor.parser.flags import Flags
from redoctor.parser.ast import has_backreferences
from redoctor.automaton.checker import AutomatonChecker
from redoctor.fuzz.checker import FuzzChecker
from redoctor.recall.validator import RecallValidator, ValidationResult
from redoctor.diagnostics.diagnostics import Diagnostics, Status
from redoctor.config import Config, CheckerType
from redoctor.exceptions import ParseError


class HybridChecker:
    """Hybrid ReDoS checker combining automaton and fuzz analysis.

    The checker automatically selects the best approach based on
    pattern features:
    - Automaton checker for patterns without backreferences
    - Fuzz checker for patterns with backreferences or complex lookaround
    - Recall validation to confirm detected vulnerabilities
    """

    def __init__(self, config: Config = None):
        self.config = config or Config.default()
        self.automaton_checker = AutomatonChecker(self.config)
        self.fuzz_checker = FuzzChecker(self.config)
        self.validator = RecallValidator(
            timeout=self.config.recall_timeout,
        )

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
        # Choose checker based on configuration and pattern features
        checker_type = self.config.checker

        if checker_type == CheckerType.AUTO:
            # Auto-select based on pattern features
            if has_backreferences(pattern.node):
                checker_type = CheckerType.FUZZ
            else:
                checker_type = CheckerType.AUTOMATON

        # Run the selected checker
        if checker_type == CheckerType.AUTOMATON:
            result = self.automaton_checker.check_pattern(pattern)

            # If automaton checker returns unknown, try fuzz
            if result.status == Status.UNKNOWN:
                result = self.fuzz_checker.check_pattern(pattern)

        else:  # FUZZ
            result = self.fuzz_checker.check_pattern(pattern)

        # Validate vulnerabilities with recall (unless skipped)
        if (
            result.is_vulnerable
            and result.attack_pattern
            and not self.config.skip_recall
        ):
            validated = self._validate_result(pattern.source, result)
            if validated:
                return result
            else:
                # Could not confirm - downgrade to unknown
                return Diagnostics.unknown(
                    pattern.source,
                    checker=result.checker,
                    message="Potential vulnerability detected but could not confirm.",
                )

        return result

    def _validate_result(self, pattern: str, result: Diagnostics) -> bool:
        """Validate a detected vulnerability.

        Args:
            pattern: The regex pattern.
            result: The detection result.

        Returns:
            True if vulnerability is confirmed.
        """
        if not result.attack_pattern:
            return False

        # Try validation with the attack pattern
        validation = self.validator.validate_with_scaling(
            pattern=pattern,
            prefix=result.attack_pattern.prefix,
            pump=result.attack_pattern.pump,
            suffix=result.attack_pattern.suffix,
            max_pump_count=30,
        )

        return validation.result == ValidationResult.CONFIRMED


def check(pattern: str, flags: Flags = None, config: Config = None) -> Diagnostics:
    """Check a regex pattern for ReDoS vulnerabilities.

    This is the main entry point for the library.

    Args:
        pattern: The regex pattern string.
        flags: Optional regex flags.
        config: Optional configuration.

    Returns:
        Diagnostics result with vulnerability information.

    Example:
        >>> from recheck import check
        >>> result = check(r"^(a+)+$")
        >>> if result.is_vulnerable:
        ...     print(f"Vulnerable: {result.complexity}")
        ...     print(f"Attack: {result.attack}")
    """
    checker = HybridChecker(config)
    return checker.check(pattern, flags)


def check_pattern(pattern: Pattern, config: Config = None) -> Diagnostics:
    """Check a parsed pattern for ReDoS vulnerabilities.

    Args:
        pattern: The parsed Pattern AST.
        config: Optional configuration.

    Returns:
        Diagnostics result.
    """
    checker = HybridChecker(config)
    return checker.check_pattern(pattern)


def is_safe(pattern: str, flags: Flags = None, config: Config = None) -> bool:
    """Quick check if a pattern is safe.

    Args:
        pattern: The regex pattern.
        flags: Optional regex flags.
        config: Optional configuration.

    Returns:
        True if the pattern is safe, False otherwise.
    """
    result = check(pattern, flags, config)
    return result.is_safe


def is_vulnerable(pattern: str, flags: Flags = None, config: Config = None) -> bool:
    """Quick check if a pattern is vulnerable.

    Args:
        pattern: The regex pattern.
        flags: Optional regex flags.
        config: Optional configuration.

    Returns:
        True if the pattern is vulnerable, False otherwise.
    """
    result = check(pattern, flags, config)
    return result.is_vulnerable
