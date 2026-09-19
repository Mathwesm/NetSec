"""Expose diagnostics and lexical-scope completions to editor integrations."""

from __future__ import annotations

from dataclasses import asdict

from pydantic import BaseModel, ConfigDict, Field

from netsec.core.compiler import compile_source
from netsec.core.lexer import KEYWORDS, TYPES, tokenize
from netsec.core.model import NetSecError, Source, Token
from netsec.core.modules import expand

_TARGETS_LOOKBEHIND = 2
_FUNCTION_HEADER_TOKENS = 2


class EditorRequest(BaseModel):
    """Validate unsaved editor text and cursor coordinates."""

    model_config = ConfigDict(extra="forbid")
    text: str = Field(max_length=1_000_000)
    filename: str = "<editor>"
    line: int = Field(default=1, ge=1)
    column: int = Field(default=1, ge=1)
    modules: dict[str, str] = Field(default_factory=dict, max_length=64)


def analyze(request: EditorRequest) -> dict[str, object]:
    """Return diagnostics and suggestions without performing network operations."""
    diagnostics: list[dict[str, object]] = []
    try:
        compile_source(request.text, request.filename, modules=request.modules)
    except NetSecError as error:
        diagnostics.append(error.diagnostic.as_dict())
    symbols = _visible_symbols(request)
    completions: list[dict[str, object]] = [
        {"label": word, "type": "keyword"} for word in sorted(KEYWORDS)
    ]
    completions.extend(symbols)
    members = _member_completions(request, symbols)
    if members:
        completions = members
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
    scopes[0].update(_imported_symbols(request))
    class_names = {
        tokens[i + 1].text for i, token in enumerate(tokens[:-1]) if token.kind == "class"
    }
    class_names.update(name for name, value in scopes[0].items() if value["type"] == "class")
    for index, token in enumerate(tokens):
        if token.kind == "{":
            scopes.append(_scope_context(tokens, index))
        elif token.kind == "}" and len(scopes) > 1:
            scopes.pop()
        elif token.kind == "NAME" and index > 0:
            previous = tokens[index - 1]
            following = tokens[index + 1].kind if index + 1 < len(tokens) else "EOF"
            if (
                (previous.kind in TYPES or previous.text in class_names) and following == "="
            ) or previous.kind in {"group", "fn", "class"}:
                scopes[-1][token.text] = _symbol(token, previous.text)
    visible: dict[str, dict[str, object]] = {}
    for scope in scopes:
        visible.update(scope)
    function_name, parameters = _function_parameters(tokens)
    if function_name:
        visible.pop(function_name, None)
        visible.update(parameters)
    return list(visible.values())


def _scope_context(tokens: tuple[Token, ...], index: int) -> dict[str, dict[str, object]]:
    if index < _TARGETS_LOOKBEHIND:
        return {}
    kind = tokens[index - _TARGETS_LOOKBEHIND].kind
    if kind == "class":
        return {
            "self": {
                "label": "self",
                "type": tokens[index - 1].text,
                "span": asdict(tokens[index].span),
            }
        }
    if kind == "targets":
        return {
            "current_host": {
                "label": "current_host",
                "type": "ip",
                "span": asdict(tokens[index].span),
            }
        }
    return {}


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
        if (
            (token.kind in TYPES or token.kind == "NAME")
            and index + 1 < len(tail)
            and tail[index + 1].kind == "NAME"
        ):
            parameter = tail[index + 1]
            parameters[parameter.text] = _symbol(parameter, token.text)
    return tail[1].text, parameters


def _symbol(token: Token, type_name: str) -> dict[str, object]:
    return {"label": token.text, "type": type_name, "span": asdict(token.span)}


def _imported_symbols(request: EditorRequest) -> dict[str, dict[str, object]]:
    try:
        tokens = tokenize(Source(text=_prefix(request), filename=request.filename))
        imports = "\n".join(
            f"import {tokens[i + 1].text};"
            for i, token in enumerate(tokens[:-1])
            if token.kind == "import" and tokens[i + 1].kind == "STRING"
        )
        source = Source(text=imports, filename=request.filename, modules=request.modules)
        program = expand(source)
    except NetSecError:
        return {}
    return {
        node.name: {
            "label": node.name,
            "type": node.type_name or node.kind,
            "span": asdict(node.span),
        }
        for node in program.statements
        if node.span.filename != request.filename
        and node.kind in {"binding", "function", "class", "group"}
    }


def _member_completions(
    request: EditorRequest, symbols: list[dict[str, object]]
) -> list[dict[str, object]]:
    try:
        prefix = tokenize(Source(text=_prefix(request)))[:-1]
        all_tokens = tokenize(Source(text=request.text, filename=request.filename))
        for filename, text in request.modules.items():
            all_tokens += tokenize(Source(text=text, filename=filename))
    except NetSecError:
        return []
    if len(prefix) < _TARGETS_LOOKBEHIND or prefix[-1].kind != ".":
        return []
    receiver = prefix[-2].text
    type_name = next((item["type"] for item in symbols if item["label"] == receiver), "")
    return _class_members(all_tokens, type_name)


def _class_members(all_tokens: tuple[Token, ...], type_name: object) -> list[dict[str, object]]:
    members: list[dict[str, object]] = []
    active, depth = False, 0
    for index, token in enumerate(all_tokens[:-1]):
        if token.kind == "class" and all_tokens[index + 1].text == type_name:
            active = True
        if not active:
            continue
        if token.kind == "{":
            depth += 1
        elif token.kind == "}":
            depth -= 1
            if depth == 0:
                break
        elif depth == 1 and token.kind == "NAME" and index > 0:
            previous, following = all_tokens[index - 1], all_tokens[index + 1]
            if previous.kind == "fn" or (following.kind == ";" and previous.kind in TYPES):
                members.append(_symbol(token, previous.text))
    return members
