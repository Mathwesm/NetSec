$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$owner = 'netsec-scheduler-v1'
if ($request.job.name -notmatch '^[a-z][a-z0-9-]{0,31}$') { throw 'Invalid job name' }
$taskName = 'NetSec-' + $request.job.name
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task -and -not $task.Description.StartsWith($owner + ':')) { throw 'Task is not owned by NetSec' }
if ($request.operation -eq 'status') {
    $state = if ($task) { [string]$task.State } else { 'absent' }
    @{ state = $state; name = $taskName } | ConvertTo-Json -Compress
    exit 0
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges required' }
if ($request.operation -eq 'remove') {
    if ($task) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    @{ status = $(if ($task) { 'removed' } else { 'unchanged' }); retained = 'Configuration and run history' } | ConvertTo-Json -Compress
    exit 0
}
if ($request.operation -ne 'install') { throw 'Unsupported scheduler operation' }
if (@($request.arguments).Count -ne 0) { throw 'Install the packaged CLI for all users before scheduling SYSTEM tasks' }

function Assert-NoReparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Scheduler paths cannot traverse reparse points' }
        $item = if ($item.PSIsContainer) { $item.Parent } else { $item.Directory }
    }
}
function Assert-Protected([string]$Path) {
    Assert-NoReparse $Path
    $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        if ($rule.AccessControlType -ne 'Allow' -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $trusted = $sid -in @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        if (-not $trusted -and ($rule.FileSystemRights -band $writeRights)) { throw 'Scheduled executable and configuration must not be writable by regular users' }
    }
}
$executable = [IO.Path]::GetFullPath([string]$request.executable)
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
if (-not $executable.StartsWith($programFiles + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'SYSTEM tasks require an all-users installation under Program Files' }
Assert-Protected $executable
$directory = [IO.Path]::GetDirectoryName($executable)
while ($directory.Length -ge $programFiles.Length) {
    Assert-Protected $directory
    $directory = [IO.Path]::GetDirectoryName($directory)
}
function New-ProtectedDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { Assert-Protected $Path; return }
    $null = New-Item -ItemType Directory -Path $Path
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-Protected $Path
}
$base = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'NetSec'
New-ProtectedDirectory $base
$root = Join-Path $base 'jobs'
New-ProtectedDirectory $root
$json = $request.job | ConvertTo-Json -Depth 50 -Compress
$hash = [Security.Cryptography.SHA256]::Create()
try { $digest = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))).Replace('-', '').ToLowerInvariant() }
finally { $hash.Dispose() }
$manifest = Join-Path $root ($request.job.name + '-' + $digest + '.json')
if (Test-Path -LiteralPath $manifest) {
    Assert-Protected $manifest
    if ([IO.File]::ReadAllText($manifest) -ne $json) { throw 'Existing immutable job revision has changed' }
} else {
    $file = [IO.File]::Open($manifest, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes = [Text.Encoding]::UTF8.GetBytes($json); $file.Write($bytes, 0, $bytes.Length) }
    finally { $file.Dispose() }
}
$runRoot = Join-Path $root ($request.job.name + '-runs')
$arguments = 'automation execute "' + $manifest + '" --apply --output-root "' + $runRoot + '"'
$description = $owner + ':' + $digest
$action = New-ScheduledTaskAction -Execute $executable -Argument $arguments -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$periodic = New-ScheduledTaskTrigger -Once -At ([DateTime]::new(2020, 1, 1)) -RepetitionInterval ([TimeSpan]::FromSeconds($request.job.interval_seconds))
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5)) -RestartCount 2 -RestartInterval ([TimeSpan]::FromMinutes(1)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$account = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$desired = New-ScheduledTask -Action $action -Trigger @($trigger, $periodic) -Settings $settings -Principal $account -Description $description
# Re-register to repair action/trigger drift, not only a matching description marker.
$unchanged = $false
if ($task) {
    $unchanged = $task.Description -eq $description -and @($task.Actions).Count -eq 1 -and $task.Actions[0].Execute -eq $executable -and $task.Actions[0].Arguments -eq $arguments -and $task.Actions[0].WorkingDirectory -eq $root -and @($task.Triggers).Count -eq 2 -and $task.Triggers[0].CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' -and $task.Triggers[1].Repetition.Interval -eq $periodic.Repetition.Interval -and $task.Principal.UserId -in @('SYSTEM', 'S-1-5-18') -and $task.Settings.MultipleInstances -eq 2 -and $task.Settings.Enabled
}
if (-not $unchanged) { $null = Register-ScheduledTask -TaskName $taskName -InputObject $desired -Force }
@{ status = $(if ($unchanged) { 'unchanged' } else { 'applied' }); manifest = $manifest } | ConvertTo-Json -Compress
