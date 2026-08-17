function New-AuditGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name = '_Audit-NTLM-Ldap',

        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h) {
        Write-Host 'Creates a new (unlinked) GPO that enables NTLM auditing and LDAP interface event logging.'
        Write-Host 'The GPO configures (all applied as Computer Preferences > Registry items):'
        Write-Host '  - Lsa\MSV1_0\AuditReceivingNTLMTraffic = 2   (Audit Incoming NTLM Traffic: enable for all accounts)'
        Write-Host '  - Lsa\MSV1_0\RestrictSendingNTLMTraffic = 1  (Outgoing NTLM traffic to remote servers: audit all)'
        Write-Host '  - Netlogon\Parameters\AuditNTLMInDomain = 7  (Audit NTLM authentication in this domain: enable all)'
        Write-Host '  - EventLog\Security\MaxSize = 2147483648     (Security log max size: 2 GB, in bytes)'
        Write-Host '  - NTDS\Diagnostics\16 LDAP Interface Events = 2'
        Write-Host '-Name: GPO display name (default: _Audit-NTLM-Ldap).'
        Write-Host 'Always creates the GPO in the current AD domain. The GPO is NOT linked.'
        Write-Host 'NOTE: these are applied as Group Policy Preferences, not native Security Options, so they'
        Write-Host '      will NOT auto-revert if the GPO is later unlinked/deleted.'
        return
    }

    if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
        Write-Error "GroupPolicy module is required but not found. Install RSAT Group Policy Management features first."
        return
    }
    Import-Module GroupPolicy -ErrorAction Stop

    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        Write-Error "ActiveDirectory module is required but not found."
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = Get-ADDomain
    $domainFqdn = $domain.DNSRoot

    # --- GPO name collision check ---
    $existing = Get-GPO -Name $Name -Domain $domainFqdn -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Error "A GPO named '$Name' already exists in $domainFqdn (Id: $($existing.Id)). Delete it or use a different -Name."
        return
    }

    Write-Verbose "Creating GPO '$Name' in domain $domainFqdn"
    try {
        $gpo = New-GPO -Name $Name -Domain $domainFqdn -ErrorAction Stop
    }
    catch {
        throw "Failed to create GPO '$Name': $($_.Exception.Message)"
    }

    # Each entry: registry key path, value name, DWord data, friendly label for -Verbose output
    $prefValues = @(
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'AuditReceivingNTLMTraffic'; Value = 2; Label = 'Audit Incoming NTLM Traffic' }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'RestrictSendingNTLMTraffic'; Value = 1; Label = 'Outgoing NTLM traffic to remote servers (audit)' }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'AuditNTLMInDomain'; Value = 7; Label = 'Audit NTLM authentication in this domain' }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security'; Name = 'MaxSize'; Value = 2147483648; Label = 'Security log maximum size (2 GB)' }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'; Name = '16 LDAP Interface Events'; Value = 2; Label = 'LDAP Interface Events logging' }
    )

    try {
        foreach ($p in $prefValues) {
            Write-Verbose "Setting $($p.Label): $($p.Key)\$($p.Name) = $($p.Value)"
            Set-GPPrefRegistryValue -Name $Name -Domain $domainFqdn -Context Computer -Action Update `
                -Key $p.Key -ValueName $p.Name -Type DWord -Value $p.Value -ErrorAction Stop | Out-Null
        }

        Write-Host "Audit GPO '$Name' created and configured ($($gpo.Id))." -ForegroundColor Green
        Write-Host "The GPO was NOT linked. Don't forget to review and link the GPO." -ForegroundColor Green
        Write-Host "Note: settings were applied as Preferences, so they will not auto-revert on unlink/delete." -ForegroundColor Yellow

        return $gpo
    }
    catch {
        try { Remove-GPO -Guid $gpo.Id -Domain $domainFqdn -ErrorAction SilentlyContinue } catch {}
        throw "Failed to configure GPO '$Name': $($_.Exception.Message)"
    }
}
