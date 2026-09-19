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


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows security descriptors")
@pytest.mark.parametrize("rights,expected", [("ReadAndExecute", "accepted"), ("Write", "rejected")])
def test_scheduler_checks_unmapped_identities_by_sid(
    tmp_path: Path, rights: str, expected: str
) -> None:
    script = """
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $request.bridge, [ref]$null, [ref]$null)
foreach ($name in @('Assert-NoReparse', 'Assert-Protected')) {
    $guard = $ast.Find({param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $name
    }, $true)
    . ([ScriptBlock]::Create($guard.Extent.Text))
}
# An in-memory ACL emulates Get-Acl's NTAccount adapter without changing filesystem ACLs.
$script:testAcl = [Security.AccessControl.DirectorySecurity]::new()
$sid = [Security.Principal.SecurityIdentifier]::new('S-1-15-2-2')
$script:testAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $sid, $request.rights, 'Allow'))
function Get-Acl { param([string]$LiteralPath) return $script:testAcl }
try { Assert-Protected $request.target; [Console]::Write('accepted') }
catch {
    if ($_.Exception.Message -like '*must not be writable*') { [Console]::Write('rejected') }
    else { throw }
}
"""
    result = command(
        "powershell",
        ["-NoProfile", "-NonInteractive", "-Command", script],
        json.dumps(
            {
                "bridge": str(Path(scheduler.__file__).with_name("scheduler_bridge.ps1")),
                "target": str(tmp_path),
                "rights": rights,
            }
        ),
    )
    assert result.strip() == expected
