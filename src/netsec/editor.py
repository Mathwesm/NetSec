"""Expose diagnostics and lexical-scope completions to editor integrations."""

from __future__ import annotations

from dataclasses import asdict

from pydantic import BaseModel, ConfigDict, Field

from netsec.core.compiler import compile_source
from netsec.core.lexer import KEYWORDS, TYPES, tokenize
from netsec.core.model import NetSecError, Source, Token

_TARGETS_LOOKBEHIND = 2
_FUNCTION_HEADER_TOKENS = 2


class EditorRequest(BaseModel):
    """Validate unsaved editor text and cursor coordinates."""

    model_config = ConfigDict(extra="forbid")
    text: str = Field(max_length=1_000_000)
    filename: str = "<editor>"
    line: int = Field(default=1, ge=1)
    column: int = Field(default=1, ge=1)


def analyze(request: EditorRequest) -> dict[str, object]:
    """Return diagnostics and suggestions without performing network operations."""
    diagnostics: list[dict[str, object]] = []
    try:
        compile_source(request.text, request.filename)
    except NetSecError as error:
        diagnostics.append(error.diagnostic.as_dict())
    symbols = _visible_symbols(request)
    completions: list[dict[str, object]] = [
        {"label": word, "type": "keyword"} for word in sorted(KEYWORDS)
    ]
    completions.extend(symbols)
    return {"diagnostics": diagnostics, "completions": completions, "symbols": symbols}


def _prefix(request: EditorRequest) -> str:
    lines = request.text.splitlines(keepends=True)
    if request.line > len(lines):
        return request.text
    return "".join(lines[: request.line - 1]) + lines[request.line - 1][: request.column - 1]


def _visible_symbols(request: EditorRequest) -> list[dict[str, object]]:
    try:
        tokens = tokenize(Source(text=_prefix(request), filename=request.filename))
    except NetSecError:
        return []
    scopes: list[dict[str, dict[str, object]]] = [{}]
    for index, token in enumerate(tokens):
        if token.kind == "{":
            scopes.append({})
            if (
                index >= _TARGETS_LOOKBEHIND
                and tokens[index - _TARGETS_LOOKBEHIND].kind == "targets"
            ):
                scopes[-1]["current_host"] = {
                    "label": "current_host",
                    "type": "ip",
                    "span": asdict(token.span),
                }
        elif token.kind == "}" and len(scopes) > 1:
            scopes.pop()
        elif token.kind == "NAME" and index > 0:
            previous = tokens[index - 1]
            following = tokens[index + 1].kind if index + 1 < len(tokens) else "EOF"
            if (previous.kind in TYPES and following == "=") or previous.kind in {"group", "fn"}:
                scopes[-1][token.text] = _symbol(token, previous.kind)
    visible: dict[str, dict[str, object]] = {}
    for scope in scopes:
        visible.update(scope)
    function_name, parameters = _function_parameters(tokens)
    if function_name:
        visible.pop(function_name, None)
        visible.update(parameters)
    return list(visible.values())


def _function_parameters(tokens: tuple[Token, ...]) -> tuple[str, dict[str, dict[str, object]]]:
    declarations = [index for index, token in enumerate(tokens) if token.kind == "fn"]
    if not declarations:
        return "", {}
    start = declarations[-1]
    tail = tokens[start:]
    if any(token.kind == ";" for token in tail) or len(tail) < _FUNCTION_HEADER_TOKENS:
        return "", {}
    parameters: dict[str, dict[str, object]] = {}
    for index, token in enumerate(tail):
        if token.kind == ")":
            break
        if token.kind in TYPES and index + 1 < len(tail) and tail[index + 1].kind == "NAME":
            parameter = tail[index + 1]
            parameters[parameter.text] = _symbol(parameter, token.kind)
    return tail[1].text, parameters


def _symbol(token: Token, type_name: str) -> dict[str, object]:
    return {"label": token.text, "type": type_name, "span": asdict(token.span)}
