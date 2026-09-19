"""Tokenize NetSec using longest-match rules and precise error locations."""

from __future__ import annotations

import re

from netsec.core.model import Source, Span, Token, fail

KEYWORDS = frozenset(
    [
        "group",
        "host",
        "address",
        "play",
        "targets",
        "check",
        "port",
        "protocol",
        "service",
        "dns",
        "expect",
        "fn",
        "class",
        "import",
        "server",
        "http",
        "response",
        "record",
        "firewall",
        "allow",
        "deny",
        "report",
        "if",
        "else",
        "repeat",
        "int",
        "bool",
        "string",
        "ip",
        "network",
        "true",
        "false",
        "tcp",
        "udp",
        "and",
        "or",
        "not",
        "in",
    ]
)
TYPES = frozenset({"int", "bool", "string", "ip", "network", "port", "protocol"})
_PATTERN = re.compile(
    r"(?P<SPACE>[ \t\r]+)|(?P<NEWLINE>\n)|(?P<COMMENT>//[^\n]*)|"
    r'(?P<STRING>"(?:[^"\\\r\n]|\\[^\r\n])*")|(?P<INT>[0-9]+)|'
    r"(?P<NAME>[A-Za-z_][A-Za-z_0-9]*)|(?P<SYMBOL>->|==|!=|<=|>=|[.{}(),;=+*/%<>-])"
)
MAX_INTEGER_DIGITS = 100


def tokenize(source: Source) -> tuple[Token, ...]:
    """Return tokens including EOF, or reject an invalid character.

    Args:
        source: Validated text and filename.

    Returns:
        Tokens with one-based positions.

    Raises:
        NetSecError: If a character, string or integer cannot be tokenized.
    """
    tokens: list[Token] = []
    offset, line, column = 0, 1, 1
    while offset < len(source.text):
        match = _PATTERN.match(source.text, offset)
        if match is None:
            fail(
                "E_LEXICAL",
                "Unexpected character or unterminated string",
                Span(source.filename, line, column, column + 1),
            )
        text = match.group()
        kind = match.lastgroup or ""
        span = Span(source.filename, line, column, column + len(text))
        if kind not in {"SPACE", "COMMENT", "NEWLINE"}:
            tokens.append(_token(kind, text, span))
        if kind == "NEWLINE":
            line, column = line + 1, 1
        else:
            column += len(text)
        offset = match.end()
    tokens.append(Token("EOF", "", Span(source.filename, line, column, column)))
    return tuple(tokens)


def _token(kind: str, text: str, span: Span) -> Token:
    if kind == "INT" and len(text) > MAX_INTEGER_DIGITS:
        fail("E_LIMIT", "Integer literal exceeds 100 digits", span)
    if kind == "SYMBOL" or (kind == "NAME" and text in KEYWORDS):
        kind = text
    return Token(kind, text, span)
