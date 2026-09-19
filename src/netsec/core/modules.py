"""Bundle bounded local imports without filesystem access during compilation."""

from pathlib import Path, PurePosixPath

from netsec.core.model import Program, Source, Span, Statement, fail
from netsec.core.parser import parse

MAX_MODULES = 64
MAX_SOURCE_TEXT = 1_000_000


def module_key(name: str, parent: str, span: Span) -> str:
    """Resolve portable relative module paths within the entry file's directory."""
    if not name or "\\" in name or ":" in name or name.startswith("/") or "\x00" in name:
        fail("E_IMPORT_PATH", "Imports require relative .netsec paths", span)
    parts: list[str] = list(PurePosixPath(parent).parent.parts) if parent else []
    for part in PurePosixPath(name).parts:
        if part == "..":
            if not parts:
                fail("E_IMPORT_PATH", "Import escapes the project directory", span)
            parts.pop()
        else:
            parts.append(part)
    key = "/".join(parts)
    if not key.endswith(".netsec"):
        fail("E_IMPORT_PATH", "Imported files must use the .netsec extension", span)
    return key


def expand(source: Source) -> Program:
    """Expand each bundled module once, detecting cycles and limiting aggregate size."""
    if len(source.text) + sum(map(len, source.modules.values())) > MAX_SOURCE_TEXT:
        fail(
            "E_LIMIT", "Combined source exceeds 1000000 characters", Span(source.filename, 1, 1, 1)
        )
    visited: set[str] = set()
    active: set[str] = set()

    def visit(text: str, key: str) -> list[Statement]:
        statements: list[Statement] = []
        for node in parse(Source(text=text, filename=key or source.filename)).statements:
            if node.kind != "import":
                statements.append(node)
                continue
            target = module_key(node.name, key, node.span)
            if target in active:
                fail("E_IMPORT_CYCLE", f"Cyclic import {target!r}", node.span)
            if target in visited:
                continue
            if target not in source.modules:
                fail("E_IMPORT", f"Module {target!r} is not in the source bundle", node.span)
            active.add(target)
            statements.extend(visit(source.modules[target], target))
            active.remove(target)
            visited.add(target)
        return statements

    return Program(tuple(visit(source.text, "")))


def _read(path: Path) -> str:
    with path.open(encoding="utf-8-sig") as stream:
        return stream.read(MAX_SOURCE_TEXT + 1)


def load_source(path: Path) -> Source:
    """Read a local project with bounded imports and reject symlink escapes.

    Args:
        path: Entry source file; its parent defines the project boundary.

    Returns:
        A self-contained source bundle suitable for remote recompilation.

    Raises:
        NetSecError: If paths escape, imports cycle or the bundle exceeds limits.
        OSError: If the entry or an imported file cannot be read.
    """
    root = path.resolve().parent
    text = _read(path)
    source = Source(text=text, filename=str(path))
    modules: dict[str, str] = {}
    pending = [("", source.text)]
    size = len(text)
    while pending:
        parent, content = pending.pop()
        for node in parse(Source(text=content, filename=parent or str(path))).statements:
            if node.kind != "import":
                continue
            key = module_key(node.name, parent, node.span)
            if key in modules:
                continue
            target = (root / key).resolve()
            if not target.is_relative_to(root):
                fail("E_IMPORT_PATH", "Import symlink escapes the project directory", node.span)
            if len(modules) >= MAX_MODULES:
                fail("E_LIMIT", "Project exceeds 64 imported modules", node.span)
            try:
                content = _read(target)
            except OSError:
                fail("E_IMPORT", f"Cannot read module {key!r}", node.span)
            size += len(content)
            if size > MAX_SOURCE_TEXT:
                fail("E_LIMIT", "Combined source exceeds 1000000 characters", node.span)
            modules[key] = content
            pending.append((key, content))
    result = Source(text=text, filename=str(path), modules=modules)
    expand(result)
    return result
