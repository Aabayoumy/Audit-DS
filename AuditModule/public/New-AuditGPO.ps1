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
        Write-Host 'The GPO configures:'
        Write-Host '  - Network security: Restrict NTLM: Audit Incoming NTLM Traffic (enable auditing for all accounts)'
        Write-Host '  - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers (audit all)'
        Write-Host '  - Network security: Restrict NTLM: Audit NTLM authentication in this domain (enable all)'
        Write-Host '  - Event Log Service Security log maximum size: 2 GB (2097152 KB)'
        Write-Host '  - Registry preference HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\16 LDAP Interface Events = 2'
        Write-Host '-Name: GPO display name (default: _Audit-NTLM-Ldap).'
        Write-Host 'Always creates the GPO in the current AD domain. The GPO is NOT linked.'
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

    $domainFqdn = (Get-ADDomain).DNSRoot

    if (Get-GPO -Name $Name -Domain $domainFqdn -ErrorAction SilentlyContinue) {
        Write-Error "A GPO named '$Name' already exists in $domainFqdn. Delete it or use a different -Name."
        return
    }

    Write-Verbose "Creating GPO '$Name' in domain $domainFqdn"
    try {
        $gpo = New-GPO -Name $Name -Domain $domainFqdn -ErrorAction Stop
    } catch {
        throw "Failed to create GPO '$Name': $($_.Exception.Message)"
    }

    try {
        $gpoSysvol = "\\$domainFqdn\SYSVOL\sysvol\$domainFqdn\Policies\$($gpo.Id)\Machine"

        $secEditDir = Join-Path $gpoSysvol 'Microsoft\Windows NT\SecEdit'
        New-Item -ItemType Directory -Path $secEditDir -Force | Out-Null
        $gptTmpl = @"
[Unicode]
Unicode=yes
[Security Log]
MaximumLogSize = 2097152
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic=4,2
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain=4,7
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        Set-Content -Path (Join-Path $secEditDir 'GptTmpl.inf') -Value $gptTmpl -Encoding Unicode

        $regPrefDir = Join-Path $gpoSysvol 'Preferences\Registry'
        New-Item -ItemType Directory -Path $regPrefDir -Force | Out-Null
        $uid = [guid]::NewGuid().ToString('D').ToUpper()
        $changed = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $regXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">
  <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="16 LDAP Interface Events" status="16 LDAP Interface Events" image="12" changed="$changed" uid="{$uid}">
    <Properties action="U" displayDecimal="1" default="0" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" name="16 LDAP Interface Events" type="REG_DWORD" value="00000002"/>
  </Registry>
</RegistrySettings>
"@
        Set-Content -Path (Join-Path $regPrefDir 'Registry.xml') -Value $regXml -Encoding UTF8

        $gpoDn = "CN=$($gpo.Id),CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"
        $adGpo = Get-ADObject -Identity $gpoDn -Properties versionNumber
        Set-ADObject -Identity $gpoDn -Replace @{
            versionNumber = [int]$adGpo.versionNumber + 0x10000
        }

        Write-Host "Audit GPO '$Name' created and saved ($($gpo.Id))." -ForegroundColor Green
        Write-Host "The GPO was NOT linked. Don't forget to review and link the GPO." -ForegroundColor Green

        return $gpo
    } catch {
        try { Remove-GPO -Guid $gpo.Id -Domain $domainFqdn -ErrorAction SilentlyContinue } catch {}
        throw "Failed to configure GPO '$Name': $($_.Exception.Message)"
    }
}
