from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FieldError:
    field: str
    message: str


class AllowlyAPIError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        fields: list[FieldError] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.fields = fields or []

    def __repr__(self) -> str:
        return f"AllowlyAPIError(status={self.status}, code={self.code!r}, message={str(self)!r})"


class AllowlyProtocolError(ValueError):
    """The API returned a response that does not match its wire contract."""
