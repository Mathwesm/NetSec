param([string]$Compiler = '', [string]$CertificateThumbprint = '')
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Push-Location -LiteralPath $project
try {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
    $destination = Join-Path $project "dist/windows-$stamp"
    $temporary = Join-Path $project "build/windows-$stamp"
    New-Item -ItemType Directory -Path $destination, $temporary | Out-Null
    $common = @('--onedir', '--distpath', $destination, '--workpath', $temporary, '--specpath', $temporary,
        '--paths', (Join-Path $project 'src'), '--collect-submodules', 'dns', '--collect-data', 'netsec', '--log-level', 'WARN',
        '--add-data', ((Join-Path $project 'src/netsec/platforms/windows_bridge.ps1') + ':netsec/platforms'),
        '--add-data', ((Join-Path $project 'src/netsec/platforms/scheduler_bridge.ps1') + ':netsec/platforms'))
    & poetry run pyinstaller @common --name NetSec packaging/windows/cli_entry.py
    if ($LASTEXITCODE -ne 0) { throw 'CLI packaging failed' }
    & poetry run pyinstaller @common --name NetSec-Desktop --windowed packaging/windows/desktop_entry.py
    if ($LASTEXITCODE -ne 0) { throw 'Desktop packaging failed' }
    & (Join-Path $destination 'NetSec/NetSec.exe') check examples/05_functions.netsec
    if ($LASTEXITCODE -ne 0) { throw 'Packaged compiler smoke test failed' }
    if ($CertificateThumbprint) {
        foreach ($binary in @('NetSec/NetSec.exe', 'NetSec-Desktop/NetSec-Desktop.exe')) {
            & (Join-Path $PSScriptRoot 'sign.ps1') -Target (Join-Path $destination $binary) -CertificateThumbprint $CertificateThumbprint
        }
    }
    if ($Compiler) {
        & $Compiler "/DBundleRoot=$destination" "/DOutputRoot=$destination/installer" packaging/windows/installer.iss
        if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed' }
        if ($CertificateThumbprint) {
            $installer = Get-ChildItem -LiteralPath (Join-Path $destination 'installer') -Filter '*.exe' | Select-Object -First 1
            & (Join-Path $PSScriptRoot 'sign.ps1') -Target $installer.FullName -CertificateThumbprint $CertificateThumbprint
        }
    }
    Write-Output "Windows package: $destination"
} finally {
    Pop-Location
}
