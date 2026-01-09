"""Command-line interface for ReDoctor."""

import argparse
import sys

from redoctor import check, Config
from redoctor.parser.flags import Flags


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="redoctor",
        description="ReDoctor - Check regular expressions for ReDoS vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  redoctor '^(a+)+$'
  redoctor '(a|a)*$' --ignore-case
  redoctor '.*(.+)+' --timeout 10
  echo '^(a+)+$' | redoctor --stdin
        """,
    )

    parser.add_argument(
        "pattern",
        nargs="?",
        help="The regex pattern to check",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read pattern from stdin (one pattern per line)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-i",
        "--ignore-case",
        action="store_true",
        help="Add IGNORECASE flag",
    )
    parser.add_argument(
        "-m",
        "--multiline",
        action="store_true",
        help="Add MULTILINE flag",
    )
    parser.add_argument(
        "-s",
        "--dotall",
        action="store_true",
        help="Add DOTALL flag",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only output status (exit code 0=safe, 1=vulnerable, 2=error)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output with attack details",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit",
    )

    args = parser.parse_args()

    if args.version:
        from redoctor import __version__

        print("ReDoctor {0}".format(__version__))
        return 0

    # Build flags
    flags = Flags(
        ignore_case=args.ignore_case,
        multiline=args.multiline,
        dotall=args.dotall,
    )

    # Build config - skip_recall to prevent hanging on vulnerable patterns
    config = Config(timeout=args.timeout, skip_recall=True)

    # Get patterns to check
    patterns = []
    if args.stdin:
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    elif args.pattern:
        patterns.append(args.pattern)
    else:
        parser.print_help()
        return 2

    # Track overall result
    has_vulnerable = False
    has_error = False

    for pattern in patterns:
        try:
            result = check(pattern, flags=flags, config=config)

            if args.quiet:
                # Quiet mode: just track status
                if result.is_vulnerable:
                    has_vulnerable = True
            elif args.verbose:
                # Verbose output
                print("Pattern: {0}".format(pattern))
                print("Status:  {0}".format(result.status.name))
                if result.complexity:
                    print("Complexity: {0}".format(result.complexity))
                if result.is_vulnerable and result.attack_pattern:
                    print("Attack pattern:")
                    print("  Prefix: {0!r}".format(result.attack_pattern.prefix))
                    print("  Pump:   {0!r}".format(result.attack_pattern.pump))
                    print("  Suffix: {0!r}".format(result.attack_pattern.suffix))
                    # Generate example attack string
                    attack = result.attack_pattern.build(20)
                    print("  Example: {0!r}".format(attack))
                if result.hotspot:
                    print("Hotspot: {0}".format(result.hotspot))
                print()
            else:
                # Normal output
                if result.is_vulnerable:
                    print("VULNERABLE: {0}".format(pattern))
                    if result.complexity:
                        print("  Complexity: {0}".format(result.complexity))
                    if result.attack_pattern:
                        attack = result.attack_pattern.build(20)
                        print("  Attack: {0!r}".format(attack))
                    has_vulnerable = True
                elif result.is_safe:
                    print("SAFE: {0}".format(pattern))
                else:
                    print("UNKNOWN: {0}".format(pattern))

        except Exception as e:
            has_error = True
            if not args.quiet:
                print("ERROR: {0}: {1}".format(pattern, e), file=sys.stderr)

    # Return appropriate exit code
    if has_error:
        return 2
    elif has_vulnerable:
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
