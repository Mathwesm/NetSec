from netsec.editor import EditorRequest, analyze
from netsec.evaluation import wrap


def test_imported_class_members_complete_in_an_unfinished_expression() -> None:
    text = 'import "server.netsec";\nServer node = Server(port(22));\nreport node.'
    result = analyze(
        EditorRequest(
            text=text,
            filename="main.netsec",
            line=4,
            modules={"server.netsec": "class Server { port management; fn base() -> int = 8000; }"},
        )
    )
    assert {item["label"]: item["type"] for item in result["completions"]} == {
        "management": "port",
        "base": "fn",
    }


def test_class_methods_complete_self_fields_without_leaking_self() -> None:
    result = analyze(
        EditorRequest(text="class Server { port management; fn value() -> port = self.", line=2)
    )
    assert "management" in {item["label"] for item in result["completions"]}
    result = analyze(EditorRequest(text="class Server { port management; }\nreport 1;", line=3))
    assert "self" not in {item["label"] for item in result["symbols"]}


def test_unsaved_semantic_error_reports_its_location() -> None:
    result = analyze(EditorRequest(text="int value = true;", filename="draft.netsec"))
    assert result["diagnostics"][0]["code"] == "E_TYPE"
    assert result["diagnostics"][0]["span"]["column"] == 13


def test_completion_knows_visible_types_and_discards_closed_scopes() -> None:
    text = wrap("port admin = port(22); if true { int hidden = 2; }\nreport admin;")
    lines = text.splitlines()
    result = analyze(EditorRequest(text=text, line=len(lines), column=3))
    symbols = {item["label"]: item["type"] for item in result["symbols"]}
    assert symbols["admin"] == "port"
    assert symbols["current_host"] == "ip"
    assert "hidden" not in symbols


def test_completion_does_not_declare_names_used_as_command_arguments() -> None:
    text = (
        'group nodes { host "one" address "192.0.2.10"; }\n'
        'play "p" targets nodes { check port unknown '
    )
    result = analyze(EditorRequest(text=text, line=2, column=len(text.splitlines()[1]) + 1))
    assert "unknown" not in {item["label"] for item in result["symbols"]}


def test_function_parameters_shadow_globals_only_inside_their_body() -> None:
    prefix = (
        'string endpoint = "global";\n'
        "fn permitted(ip endpoint, network subnet) -> bool = endpoint in "
    )
    inside = analyze(EditorRequest(text=prefix, line=3))
    symbols = {item["label"]: item["type"] for item in inside["symbols"]}
    assert symbols["endpoint"] == "ip"
    assert symbols["subnet"] == "network"
    assert "permitted" not in symbols
    finished = prefix + "subnet;\nreport endpoint;"
    outside = analyze(EditorRequest(text=finished, line=4))
    symbols = {item["label"]: item["type"] for item in outside["symbols"]}
    assert symbols["endpoint"] == "string"
    assert symbols["permitted"] == "fn"
    assert "subnet" not in symbols
