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
        Write-Host 'Applied as native Security Options (GptTmpl.inf):'
        Write-Host '  - Network security: Restrict NTLM: Audit Incoming NTLM Traffic (enable auditing for all accounts)'
        Write-Host '  - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers (audit all)'
        Write-Host '  - Network security: Restrict NTLM: Audit NTLM authentication in this domain (enable all)'
        Write-Host '  - Event Log Service Security log maximum size: 2 GB (2097152 KB)'
        Write-Host 'Applied as a Preference (no native policy exists for this value):'
        Write-Host '  - Registry HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\16 LDAP Interface Events = 2'
        Write-Host '-Name: GPO display name (default: _Audit-NTLM-Ldap).'
        Write-Host 'Always creates the GPO in the current AD domain. The GPO is NOT linked.'
        Write-Host 'Self-contained: no GPO backup files are required or shipped; the SYSVOL content is written'
        Write-Host 'directly under the new GPO''s own GUID after creation.'
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
    $existingGpo = Get-GPO -Name $Name -Domain $domainFqdn -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Error "A GPO named '$Name' already exists in $domainFqdn (Id: $($existingGpo.Id)). Delete it or use a different -Name."
        return
    }

    # --- 1. Create the (empty) GPO and grab its GUID ---
    Write-Verbose "Creating GPO '$Name' in domain $domainFqdn"
    try {
        $gpo = New-GPO -Name $Name -Domain $domainFqdn -ErrorAction Stop
    } catch {
        throw "Failed to create GPO '$Name': $($_.Exception.Message)"
    }
    $gpoGuid = $gpo.Id.ToString('B').ToUpper()   # "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
    Write-Verbose "New GPO GUID: $gpoGuid"

    try {
        $gpoRoot    = "\\$domainFqdn\SYSVOL\sysvol\$domainFqdn\Policies\$gpoGuid"
        $gpoMachine = Join-Path $gpoRoot 'Machine'
        $gptIniPath = Join-Path $gpoRoot 'gpt.ini'

        # --- 2. Write GptTmpl.inf (native Security Options: NTLM auditing + Security log size) ---
        $secEditDir = Join-Path $gpoMachine 'Microsoft\Windows NT\SecEdit'
        New-Item -ItemType Directory -Path $secEditDir -Force | Out-Null
        $gptTmpl = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Security Log]
MaximumLogSize = 2097152
[Registry Values]
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain=4,7
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic=4,2
"@
        Set-Content -Path (Join-Path $secEditDir 'GptTmpl.inf') -Value $gptTmpl -Encoding Unicode

        # --- 3. Write Registry.xml (Preference: LDAP Interface Events) ---
        $regPrefDir = Join-Path $gpoMachine 'Preferences\Registry'
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

        # --- 4. Tell clients to actually run the Security + Registry-Preference engines for this GPO.
        #        Fresh GPO -> gPCMachineExtensionNames starts empty, so this can be one hardcoded,
        #        pre-sorted (ascending by CSE GUID) string; no merge with prior values needed. ---
        $gpcExtensionNames = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]' + `
                             '[{B087BE9D-ED37-454F-AF9C-04291E351182}{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}]'

        # Deliberately NOT forcing -Server $pdcHost here: New-GPO succeeded without it, and forcing a
        # specific DC for the follow-up read/write was causing a consistent (non-transient) failure —
        # let the ActiveDirectory module fall back to its normal default DC targeting instead.
        $adGpo = $null
        for ($i = 0; $i -lt 15 -and -not $adGpo; $i++) {
            $adGpo = Get-ADObject -Identity $gpo.Id -Properties versionNumber -ErrorAction SilentlyContinue
            if (-not $adGpo) { Start-Sleep -Seconds 2 }
        }
        if (-not $adGpo) {
            throw "GPO AD container not found for GUID $gpoGuid. Confirm the GPO was created and AD replication completed."
        }

        # New GPO starts at version 0; bump the low 16 bits (computer/machine version) by 1.
        $newVer = ([int]$adGpo.versionNumber -band 0xFFFF0000) -bor ((([int]$adGpo.versionNumber -band 0xFFFF) + 1) -band 0xFFFF)

        Write-Verbose "Setting gPCMachineExtensionNames and bumping version to $newVer at $($adGpo.DistinguishedName)"
        $writeOk = $false
        $lastWriteError = $null
        for ($i = 0; $i -lt 10 -and -not $writeOk; $i++) {
            try {
                Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{
                    gPCMachineExtensionNames = $gpcExtensionNames
                    versionNumber            = [int]$newVer
                } -ErrorAction Stop
                $writeOk = $true
            } catch {
                $lastWriteError = $_
                Start-Sleep -Seconds 2
            }
        }
        if (-not $writeOk) { throw $lastWriteError }

        # --- 5. Keep SYSVOL's gpt.ini in sync with the AD version number ---
        if (Test-Path $gptIniPath) {
            $gptContent = Get-Content -Path $gptIniPath -Raw
            if ($gptContent -match '(?m)^Version=\d+') {
                $gptContent = $gptContent -replace '(?m)^Version=\d+', "Version=$newVer"
            } else {
                $gptContent = $gptContent.TrimEnd() + "`r`nVersion=$newVer`r`n"
            }
        } else {
            $gptContent = "[General]`r`nVersion=$newVer`r`n"
        }
        Set-Content -Path $gptIniPath -Value $gptContent -Encoding ASCII -NoNewline

        Write-Host "Audit GPO '$Name' created and configured ($gpoGuid)." -ForegroundColor Green
        Write-Host "The GPO was NOT linked. Don't forget to review and link the GPO." -ForegroundColor Green

        return $gpo
    } catch {
        try { Remove-GPO -Guid $gpo.Id -Domain $domainFqdn -ErrorAction SilentlyContinue } catch {}
        $exType = $_.Exception.GetType().FullName
        $exMsg  = $_.Exception.Message
        $inner  = if ($_.Exception.InnerException) { " | Inner: $($_.Exception.InnerException.Message)" } else { '' }
        throw "Failed to configure GPO '$Name': [$exType] $exMsg$inner"
    }
}
