"""Tests for the CLI module."""

import subprocess
import sys


class TestCLI:
    """Test CLI functionality."""

    def run_cli(self, args, input_text=None):
        """Run the CLI and return result."""
        cmd = [sys.executable, "-m", "redoctor.cli"] + args
        # Use stdout/stderr=PIPE instead of capture_output for Python 3.6 compat
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,  # Python 3.6 compat for text=True
            input=input_text,
            timeout=30,
        )
        return result

    def test_help(self):
        """Test --help flag."""
        result = self.run_cli(["--help"])
        assert result.returncode == 0
        assert "Check regular expressions" in result.stdout
        assert "--timeout" in result.stdout

    def test_version(self):
        """Test --version flag."""
        result = self.run_cli(["--version"])
        assert result.returncode == 0
        assert "ReDoctor" in result.stdout or "redoctor" in result.stdout.lower()

    def test_check_safe_pattern(self):
        """Test checking a safe pattern."""
        result = self.run_cli([r"^hello$"])
        assert result.returncode in (0, 1)  # Safe or vulnerable
        assert result.stdout  # Should have output

    def test_check_pattern_quiet(self):
        """Test quiet mode."""
        result = self.run_cli([r"^hello$", "--quiet"])
        # Quiet mode should have minimal output
        assert result.returncode in (0, 1, 2)

    def test_check_pattern_verbose(self):
        """Test verbose mode."""
        result = self.run_cli([r"^\d+$", "--verbose"])
        assert result.returncode in (0, 1)
        assert "Pattern:" in result.stdout or "Status:" in result.stdout

    def test_stdin_single(self):
        """Test reading from stdin."""
        result = self.run_cli(["--stdin"], input_text=r"^hello$")
        assert result.returncode in (0, 1)

    def test_stdin_multiple(self):
        """Test reading multiple patterns from stdin."""
        patterns = r"^hello$" + "\n" + r"^\d+$" + "\n"
        result = self.run_cli(["--stdin"], input_text=patterns)
        assert result.returncode in (0, 1)

    def test_invalid_pattern(self):
        """Test invalid pattern handling."""
        result = self.run_cli([r"(unclosed"])
        # Invalid patterns return UNKNOWN status, not an error
        assert result.returncode in (0, 1, 2)
        assert "UNKNOWN" in result.stdout or "ERROR" in result.stderr

    def test_no_pattern(self):
        """Test no pattern provided."""
        result = self.run_cli([])
        assert result.returncode == 2  # Should show help and exit with error

    def test_timeout_flag(self):
        """Test --timeout flag."""
        result = self.run_cli([r"^hello$", "--timeout", "5"])
        assert result.returncode in (0, 1)

    def test_flags(self):
        """Test regex flags."""
        result = self.run_cli([r"^[a-z]+$", "--ignore-case"])
        assert result.returncode in (0, 1)

        result = self.run_cli([r"^.$", "--dotall"])
        assert result.returncode in (0, 1)

        result = self.run_cli([r"^$", "--multiline"])
        assert result.returncode in (0, 1)


class TestCLIExitCodes:
    """Test CLI exit code semantics for batch mode."""

    def run_cli(self, args, input_text=None):
        """Run the CLI and return result."""
        cmd = [sys.executable, "-m", "redoctor.cli"] + args
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            input=input_text,
            timeout=30,
        )
        return result

    def test_exit_code_0_safe(self):
        """Exit code 0 for safe patterns."""
        result = self.run_cli(["--quiet", "--stdin"], input_text="^hello$\n")
        assert result.returncode == 0

    def test_exit_code_1_vulnerable(self):
        """Exit code 1 for vulnerable patterns."""
        result = self.run_cli(["--quiet", "--stdin"], input_text="^(a+)+$\n")
        assert result.returncode == 1

    def test_exit_code_2_error_only(self):
        """Exit code 2 for error-only input."""
        result = self.run_cli(["--quiet", "--stdin"], input_text="(unclosed\n")
        assert result.returncode == 2

    def test_exit_code_3_both_error_and_vulnerable(self):
        """Exit code 3 when both errors and vulnerabilities are found."""
        patterns = "^(a+)+$\n(unclosed\n"
        result = self.run_cli(["--quiet", "--stdin"], input_text=patterns)
        assert result.returncode == 3

    def test_quiet_help_text_documents_exit_codes(self):
        """Help text should document all exit codes including 3."""
        result = self.run_cli(["--help"])
        assert "3=both" in result.stdout


class TestCLIEntryPoint:
    """Test CLI entry point."""

    def test_module_runnable(self):
        """Test that module is runnable with python -m."""
        # Use stdout/stderr=PIPE instead of capture_output for Python 3.6 compat
        result = subprocess.run(
            [sys.executable, "-m", "redoctor.cli", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,  # Python 3.6 compat for text=True
            timeout=10,
        )
        assert result.returncode == 0
        assert "redoctor" in result.stdout.lower()
