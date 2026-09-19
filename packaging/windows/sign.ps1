param(
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'
$file = Get-Item -LiteralPath $Target
if ($file.Extension -ne '.exe') { throw 'Signing requires an existing executable' }
$certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $CertificateThumbprint)
if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::Now) { throw 'A valid code-signing certificate with its private key is required' }
if (-not ($certificate.EnhancedKeyUsageList.ObjectId.Value -contains '1.3.6.1.5.5.7.3.3')) { throw 'Certificate is not authorized for code signing' }
$tool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $tool) { throw 'Install Windows SDK SignTool and add it to this build process PATH' }
& $tool.Source sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 $file.FullName
if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed' }
& $tool.Source verify /pa /all /v $file.FullName
if ($LASTEXITCODE -ne 0) { throw 'Authenticode trust verification failed; artifact is not ready for publication' }
$signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint) { throw 'Signed publisher verification failed' }
Write-Output ('Verified Authenticode signature: ' + $file.Name)
