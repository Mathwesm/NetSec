"""Immutable syntax trees, source locations and compiler diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field

type Scalar = str | int | bool
type ExpressionKind = Literal["literal", "name", "unary", "binary", "convert", "call"]
type StatementKind = Literal[
    "binding",
    "group",
    "host",
    "play",
    "port",
    "service",
    "dns",
    "firewall",
    "report",
    "if",
    "repeat",
    "function",
]
MAX_EXPRESSION_HEIGHT = 100


class Source(BaseModel):
    """Validate source text before lexical analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    text: str = Field(max_length=1_000_000)
    filename: str = Field(default="<input>", min_length=1)


@dataclass(frozen=True, slots=True)
class Span:
    """Identify a source range with one-based Unicode character positions."""

    filename: str
    line: int
    column: int
    end_column: int


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """Describe an error and optionally the conflicting declaration."""

    code: str
    message: str
    span: Span
    related: Span | None = None

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-compatible diagnostic object."""
        return asdict(self)

    def __str__(self) -> str:
        """Render a terminal-friendly error location and explanation."""
        location = f"{self.span.filename}:{self.span.line}:{self.span.column}"
        return f"{location}: {self.code}: {self.message}"


class NetSecError(Exception):
    """Expose a source-aware language error without a Python traceback."""

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(str(diagnostic))


def fail(code: str, message: str, span: Span, related: Span | None = None) -> NoReturn:
    """Raise a source-aware compilation error.

    Args:
        code: Stable diagnostic identifier.
        message: Human-readable explanation.
        span: Source location of the error.
        related: Optional location of a previous declaration.

    Raises:
        NetSecError: Always.
    """
    raise NetSecError(Diagnostic(code, message, span, related))


@dataclass(frozen=True, slots=True)
class Token:
    """Represent a lexeme and its original location."""

    kind: str
    text: str
    span: Span


@dataclass(frozen=True, slots=True)
class Expression:
    """Represent one expression without evaluating Python source."""

    kind: ExpressionKind
    value: Scalar
    span: Span
    operands: tuple[Expression, ...] = ()
    type_name: str = ""
    height: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Bound every expression tree before recursive visitors can consume it."""
        height = 1 + max((operand.height for operand in self.operands), default=0)
        if height > MAX_EXPRESSION_HEIGHT:
            fail("E_LIMIT", "Expression tree exceeds 100 levels", self.span)
        object.__setattr__(self, "height", height)


@dataclass(frozen=True, slots=True)
class Parameter:
    """Declare a function parameter with an explicit domain type."""

    name: str
    type_name: str
    span: Span


@dataclass(frozen=True, slots=True)
class Statement:
    """Represent a declaration, control structure or domain instruction."""

    kind: StatementKind
    span: Span
    name: str = ""
    type_name: str = ""
    expression: Expression | None = None
    protocol: Expression | None = None
    body: tuple[Statement, ...] = ()
    alternate: tuple[Statement, ...] = ()
    target: str = ""
    expected: Expression | None = None
    parameters: tuple[Parameter, ...] = ()


@dataclass(frozen=True, slots=True)
class Program:
    """Store the top-level syntax tree."""

    statements: tuple[Statement, ...]
