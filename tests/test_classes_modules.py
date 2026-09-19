from pathlib import Path

import pytest

from netsec.core.compiler import compile_source
from netsec.core.model import NetSecError
from netsec.core.modules import load_source


def test_classes_construct_typed_values_and_call_methods() -> None:
    plan = compile_source("""
class Server {
    ip endpoint;
    port management;
    fn belongs(network subnet) -> bool = self.endpoint in subnet;
    fn shifted(int offset) -> port = port(8000 + offset);
}
Server node = Server(ip("192.0.2.10"), port(22));
fn endpoint(Server node) -> ip = node.endpoint;
group fleet { host "node" address endpoint(node); }
play "audit" targets fleet {
    check port node.management protocol tcp;
    report node.belongs(network("192.0.2.0/24"));
    report node.shifted(80);
}
""")
    assert [(item.host, item.port, item.message) for item in plan.instructions] == [
        ("192.0.2.10", 22, ""),
        ("192.0.2.10", 0, "true"),
        ("192.0.2.10", 0, "8080"),
    ]


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("class Item { int size; } Item x = Item(true);", "E_TYPE"),
        ("class Item { int size; } Item x = Item();", "E_ARITY"),
        ("class Item { int size; } report Item(1).missing;", "E_MEMBER"),
        ("class Item { int size; int size; }", "E_DUPLICATE"),
        ("class Item { Unknown size; }", "E_TYPE"),
        ("class Item { fn bad() -> bool = 42; }", "E_TYPE"),
        ("class Item { fn bad() -> int = self.missing; }", "E_MEMBER"),
        ("class Item { int size; } report Item(1);", "E_TYPE"),
        ("class Item { int size; } fn unused(Unknown a) -> int = 1;", "E_TYPE"),
    ],
)
def test_classes_reject_invalid_programs(text: str, code: str) -> None:
    with pytest.raises(NetSecError, match=code):
        compile_source(text)


def test_nested_classes_and_value_equality() -> None:
    plan = compile_source("""
class Address { ip value; }
class Server { Address endpoint; }
Server node = Server(Address(ip("192.0.2.1")));
report node.endpoint.value;
report Address(ip("192.0.2.1")) == Address(ip("192.0.2.2"));
""")
    assert [item.message for item in plan.instructions] == ["192.0.2.1", "false"]


def test_module_imports_are_resolved_once_and_keep_locations(tmp_path: Path) -> None:
    (tmp_path / "shared.netsec").write_text("fn answer() -> int = 42;", encoding="utf-8")
    entry = tmp_path / "main.netsec"
    entry.write_text(
        'import "shared.netsec"; import "shared.netsec"; report answer();', encoding="utf-8"
    )
    source = load_source(entry)
    plan = compile_source(source.text, source.filename, modules=source.modules)
    assert plan.instructions[0].message == "42"


def test_module_cycles_and_missing_modules_are_located() -> None:
    with pytest.raises(NetSecError, match="E_IMPORT_CYCLE"):
        compile_source('import "a.netsec";', modules={"a.netsec": 'import "a.netsec";'})
    with pytest.raises(NetSecError, match="E_IMPORT"):
        compile_source('import "absent.netsec";')


def test_import_cannot_read_outside_project(tmp_path: Path) -> None:
    entry = tmp_path / "main.netsec"
    entry.write_text('import "../private.netsec";', encoding="utf-8")
    with pytest.raises(NetSecError, match="E_IMPORT_PATH"):
        load_source(entry)
