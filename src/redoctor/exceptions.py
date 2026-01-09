"""Custom exceptions for ReDoctor."""


class RedoctorError(Exception):
    """Base exception for all ReDoctor errors."""

    pass


# Alias for backwards compatibility
RecheckError = RedoctorError


class ParseError(RedoctorError):
    """Raised when a regex pattern cannot be parsed."""

    def __init__(self, message: str, position: int = -1) -> None:
        self.position = position
        super().__init__(message)

    def __str__(self) -> str:
        if self.position >= 0:
            return f"{super().__str__()} at position {self.position}"
        return super().__str__()


class TimeoutError(RedoctorError):
    """Raised when analysis times out."""

    pass


class CancelledException(RedoctorError):
    """Raised when analysis is cancelled."""

    pass


class InvalidRegexError(RedoctorError):
    """Raised when the regex is invalid."""

    pass
