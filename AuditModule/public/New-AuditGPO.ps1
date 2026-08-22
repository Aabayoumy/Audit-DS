function New-AuditGPO {
    [CmdletBinding()]
    param(
        [string]$Name = '_Audit-NTLM-Ldap',

        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h) {
        Write-Host 'Creates a new, unlinked GPO using GroupPolicy cmdlets only.'
        Write-Host 'The GPO sets these computer registry policy values:'
        Write-Host '  - AuditReceivingNTLMTraffic = 2'
        Write-Host '  - RestrictSendingNTLMTraffic = 1'
        Write-Host '  - AuditNTLMInDomain = 7'
        Write-Host '  - Security event log MaxSize = 2097152 KB (2 GB)'
        Write-Host '  - NTDS Diagnostics: 16 LDAP Interface Events = 2'
        Write-Host '-Name: GPO display name (default: _Audit-NTLM-Ldap).'
        Write-Host 'The GPO is not linked automatically.'
        return
    }

    if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
        Write-Error 'GroupPolicy module is required. Install the Group Policy Management feature first.'
        return
    }
    Import-Module GroupPolicy -ErrorAction Stop

    if (Get-GPO -Name $Name -ErrorAction SilentlyContinue) {
        Write-Error "A GPO named '$Name' already exists. Delete it or use a different -Name."
        return
    }

    try {
        $gpo = New-GPO -Name $Name -ErrorAction Stop

        Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ValueName 'AuditReceivingNTLMTraffic' -Type DWord -Value 2 -ErrorAction Stop
        Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ValueName 'RestrictSendingNTLMTraffic' -Type DWord -Value 1 -ErrorAction Stop
        Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ValueName 'AuditNTLMInDomain' -Type DWord -Value 7 -ErrorAction Stop
        Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security' -ValueName 'MaxSize' -Type DWord -Value ([uint32]2147483648) -ErrorAction Stop
        Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '16 LDAP Interface Events' -Type DWord -Value 2 -ErrorAction Stop
    } catch {
        if ($gpo) {
            Remove-GPO -Guid $gpo.Id -ErrorAction SilentlyContinue
        }
        throw "Failed to create GPO '$Name': $($_.Exception.Message)"
    }

    Write-Host "Audit GPO '$Name' created ($($gpo.Id))." -ForegroundColor Green
    Write-Host 'The GPO was not linked. Review it in GPMC, then link it where required.' -ForegroundColor Green
    return $gpo
}
