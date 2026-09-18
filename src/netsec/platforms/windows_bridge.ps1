$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$owner = 'netsec-managed-v1'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($request.operation -eq 'inspect') {
    $addresses = @(Get-NetIPAddress | ForEach-Object { $_.IPAddress })
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    @{
        platform = 'windows'; addresses = $addresses; can_manage = $elevated
        firewall_enabled = ($profiles.Count -gt 0 -and @($profiles | Where-Object { -not $_.Enabled }).Count -eq 0)
        detail = 'NetSecurity available; native changes require an elevated process; all profiles must be enabled'
    } | ConvertTo-Json -Compress
    exit 0
}

if (-not $elevated) { throw 'Administrator privileges required' }
if ($request.operation -notin @('ensure', 'remove', 'exists')) { throw 'Invalid operation' }
if ($request.key -notmatch '^NetSec-[a-f0-9]{24}$') { throw 'Invalid managed rule name' }
$rule = $request.rule
$address = [System.Net.IPAddress]::Parse($rule.host).ToString()
if ($rule.protocol -notin @('tcp', 'udp') -or $rule.action -notin @('allow', 'deny')) { throw 'Invalid rule' }
if ($rule.port -lt 1 -or $rule.port -gt 65535) { throw 'Invalid port' }
if ($request.tag -ne "${owner}:$($request.key):$($rule.action)") { throw 'Invalid ownership tag' }
$existing = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -eq $request.key })
if ($existing.Count -gt 1) { throw 'Ambiguous managed rule' }
if ($existing.Count -eq 1 -and $existing[0].Group -ne $owner) { throw 'Rule name is owned by another application' }
if ($request.operation -eq 'exists') {
    $status = if ($existing.Count -eq 1) { 'present' } else { 'absent' }
    @{success = $true; status = $status; detail = 'Managed rule presence checked'} | ConvertTo-Json -Compress
    exit 0
}

if ($request.operation -eq 'remove') {
    if ($existing.Count -eq 1) {
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $request.key
        @{success = $true; status = 'removed'; detail = 'Managed Windows rule removed'} | ConvertTo-Json -Compress
    } else {
        @{success = $true; status = 'unchanged'; detail = 'Managed rule is already absent'} | ConvertTo-Json -Compress
    }
    exit 0
}

$action = if ($rule.action -eq 'allow') { 'Allow' } else { 'Block' }
$protocol = if ($rule.protocol -eq 'tcp') { 'TCP' } else { 'UDP' }
$parameters = @{
    PolicyStore = 'PersistentStore'; Name = $request.key; Description = $request.tag
    Enabled = 'True'; Direction = 'Inbound'; Action = $action; Profile = 'Any'
    Protocol = $protocol; LocalAddress = $address; LocalPort = [int]$rule.port
    RemoteAddress = 'Any'; RemotePort = 'Any'; InterfaceAlias = 'Any'; InterfaceType = 'Any'
    EdgeTraversalPolicy = 'Block'; Program = 'Any'; Service = 'Any'
}
if ($existing.Count -eq 1) {
    $current = $existing[0]
    $portFilter = $current | Get-NetFirewallPortFilter
    $addressFilter = $current | Get-NetFirewallAddressFilter
    $applicationFilter = $current | Get-NetFirewallApplicationFilter
    $serviceFilter = $current | Get-NetFirewallServiceFilter
    $interfaceFilter = $current | Get-NetFirewallInterfaceFilter
    $interfaceType = $current | Get-NetFirewallInterfaceTypeFilter
    $matches = ($current.Description -eq $request.tag -and $current.Enabled -eq 'True' -and
        $current.Direction -eq 'Inbound' -and $current.Action -eq $action -and $current.Profile -eq 'Any' -and
        $current.EdgeTraversalPolicy -eq 'Block' -and $portFilter.Protocol -eq $protocol -and
        ($portFilter.LocalPort -join ',') -eq [string]$rule.port -and ($portFilter.RemotePort -join ',') -eq 'Any' -and
        ($addressFilter.LocalAddress -join ',') -eq $address -and ($addressFilter.RemoteAddress -join ',') -eq 'Any' -and
        $applicationFilter.Program -eq 'Any' -and $serviceFilter.Service -eq 'Any' -and
        ($interfaceFilter.InterfaceAlias -join ',') -eq 'Any' -and $interfaceType.InterfaceType -eq 'Any')
    if ($matches) {
        @{success = $true; status = 'unchanged'; detail = 'Native Windows rule matches desired policy'} | ConvertTo-Json -Compress
        exit 0
    }
    Set-NetFirewallRule @parameters
} else {
    New-NetFirewallRule @parameters -DisplayName $request.key -Group $owner | Out-Null
}
@{success = $true; status = 'applied'; detail = 'Native Windows inbound rule applied; effective policy may be constrained by GPO'} | ConvertTo-Json -Compress
