param([Parameter(Mandatory = $true)][string]$Cli)
$ErrorActionPreference = 'Stop'
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
$name = 'scheduler-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$destination = Join-Path (Get-Location) ('data/processed/windows-scheduler-' + $stamp)
$null = New-Item -ItemType Directory -Path $destination
$manifest = Join-Path $destination 'job.json'
$job = @{ name = $name; source = @{ text = 'report 42;'; filename = '<scheduler-test>' }; mode = 'network'; interval_seconds = 60 }
$job | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifest -Encoding UTF8
$taskName = 'NetSec-' + $name
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Test task already exists' }
$evidence = @{}
try {
    $first = & $Cli automation install $manifest --apply | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Job installation failed' }
    $second = & $Cli automation install $manifest --apply | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Job reconciliation failed' }
    if ($first.status -ne 'applied' -or $second.status -ne 'unchanged') { throw 'Job is not idempotent' }
    Start-ScheduledTask -TaskName $taskName
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        Start-Sleep -Milliseconds 250
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $task = Get-ScheduledTask -TaskName $taskName
    } while (($info.LastRunTime.Year -lt 2026 -or $task.State -eq 'Running') -and [DateTime]::UtcNow -lt $deadline)
    if ($info.LastTaskResult -ne 0) { throw ('Scheduled execution failed: ' + $info.LastTaskResult) }
    $runRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('NetSec/jobs/' + $name + '-runs')
    $resultFile = Get-ChildItem -LiteralPath $runRoot -Recurse -Filter result.json | Select-Object -First 1
    if (-not $resultFile) { throw 'Scheduled job produced no durable evidence' }
    $result = Get-Content -LiteralPath $resultFile.FullName -Raw | ConvertFrom-Json
    if (-not $result.success -or $result.instructions -ne 1) { throw 'Scheduled report did not execute' }
    $evidence = @{ success = $true; initial = $first.status; repeated = $second.status; exit_code = $info.LastTaskResult; result = $result; boot_trigger = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' }).Count -eq 1 }
} finally {
    & $Cli automation remove $manifest --apply
    if ($LASTEXITCODE -ne 0) { throw 'Owned task cleanup failed' }
    $evidence | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $destination 'evidence.json') -Encoding UTF8
}
Write-Output ('Windows scheduler integration passed: ' + $destination)
