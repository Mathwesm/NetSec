import json
import platform
from pathlib import Path

import pytest

from netsec.platforms import scheduler
from netsec.platforms.process import command


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows filesystem metadata")
@pytest.mark.parametrize("is_directory", [False, True])
def test_scheduler_accepts_regular_nested_paths(tmp_path: Path, is_directory: bool) -> None:
    target = tmp_path / "nested"
    target.mkdir()
    if not is_directory:
        target = target / "application.exe"
        target.write_bytes(b"fixture")
    # Load only the real path guard; do not invoke scheduler operations or elevation.
    script = """
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $request.bridge, [ref]$null, [ref]$null)
$guard = $ast.Find({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Assert-NoReparse'
}, $true)
. ([ScriptBlock]::Create($guard.Extent.Text))
Assert-NoReparse $request.target
[Console]::Write('accepted')
"""
    result = command(
        "powershell",
        ["-NoProfile", "-NonInteractive", "-Command", script],
        json.dumps(
            {
                "bridge": str(Path(scheduler.__file__).with_name("scheduler_bridge.ps1")),
                "target": str(target),
            }
        ),
    )
    assert result.strip() == "accepted"
