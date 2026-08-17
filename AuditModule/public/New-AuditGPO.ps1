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
        Write-Host 'Applied as native Security Options (via GptTmpl.inf), matching a GPO exported from GPMC:'
        Write-Host '  - Network security: Restrict NTLM: Audit Incoming NTLM Traffic (enable auditing for all accounts)'
        Write-Host '  - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers (audit all)'
        Write-Host '  - Network security: Restrict NTLM: Audit NTLM authentication in this domain (enable all)'
        Write-Host '  - Event Log Service Security log maximum size: 2 GB (2097152 KB)'
        Write-Host 'Applied as a Preference (matches how GPMC itself represents this setting, no native policy exists for it):'
        Write-Host '  - Registry HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\16 LDAP Interface Events = 2'
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

    # Merge a {CSE-GUID}{Tool-GUID} pair into an existing gPCMachineExtensionNames value.
    # CSE GUID pairs must be sorted ascending (case-insensitive) or the client may skip the extension.
    function Merge-GPCExtensionGuid {
        param(
            [AllowNull()][string]$Current,
            [Parameter(Mandatory)][string]$CseGuid,
            [Parameter(Mandatory)][string]$ToolGuid
        )
        $pairs = [System.Collections.Generic.List[string]]::new()
        if ($Current) {
            foreach ($m in [regex]::Matches($Current, '\[(\{[0-9A-Fa-f-]{36}\})(\{[0-9A-Fa-f-]{36}\})\]')) {
                $pairs.Add("[$($m.Groups[1].Value)$($m.Groups[2].Value)]")
            }
        }
        $alreadyPresent = $pairs | Where-Object { $_ -like "[$CseGuid*" }
        if (-not $alreadyPresent) {
            $pairs.Add("[$CseGuid$ToolGuid]")
        }
        ($pairs | Sort-Object { ($_ -replace '^\[(\{[0-9A-Fa-f-]+\}).*', '$1').ToUpperInvariant() }) -join ''
    }

    # Bump only the computer/machine half (low 16 bits) of a packed GPO version number by 1,
    # rolling into the user half (high 16 bits) on overflow, per MS-GPOL version packing.
    function Step-GPOVersion {
        param([int64]$CurrentVersion)
        if (-not $CurrentVersion) { $CurrentVersion = 0 }
        $userPart = ($CurrentVersion -shr 16) -band 0xFFFF
        $machinePart = ($CurrentVersion -band 0xFFFF)
        $machinePart = ($machinePart + 1) -band 0xFFFF
        if ($machinePart -eq 0) { $userPart = ($userPart + 1) -band 0xFFFF }
        [int64](($userPart -shl 16) -bor $machinePart)
    }

    $domain = Get-ADDomain
    $domainFqdn = $domain.DNSRoot
    $pdcHost = $domain.PDCEmulator

    # --- GPO name collision check ---
    $existingGpo = Get-GPO -Name $Name -Domain $domainFqdn -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Error "A GPO named '$Name' already exists in $domainFqdn (Id: $($existingGpo.Id)). Delete it or use a different -Name."
        return
    }

    Write-Verbose "Creating GPO '$Name' in domain $domainFqdn"
    try {
        $gpo = New-GPO -Name $Name -Domain $domainFqdn -ErrorAction Stop
    } catch {
        throw "Failed to create GPO '$Name': $($_.Exception.Message)"
    }

    try {
        $gpoRoot    = "\\$domainFqdn\SYSVOL\sysvol\$domainFqdn\Policies\$($gpo.Id)"
        $gpoMachine = Join-Path $gpoRoot 'Machine'
        $gptIniPath = Join-Path $gpoRoot 'gpt.ini'

        # --- 1. LDAP Interface Events: kept as a Preference item (no native policy exists for this value;
        #        this mirrors how the reference GPO backup itself represents it). This cmdlet handles its
        #        own CSE registration and version bump internally. ---
        Write-Verbose "Setting LDAP Interface Events (Preference): NTDS\Diagnostics\16 LDAP Interface Events = 2"
        Set-GPPrefRegistryValue -Name $Name -Domain $domainFqdn -Context Computer -Action Update `
            -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '16 LDAP Interface Events' `
            -Type DWord -Value 2 -ErrorAction Stop | Out-Null

        # --- 2. NTLM auditing + Security log size: native Security Options via GptTmpl.inf,
        #        formatted to match the reference GPO backup. ---
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

        # --- 3. Register the Security CSE so clients actually process GptTmpl.inf, and bump versions. ---
        $secCse  = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
        $secTool = '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'

        $adGpo = $null
        for ($i = 0; $i -lt 15 -and -not $adGpo; $i++) {
            $adGpo = Get-ADObject -Server $pdcHost -Identity $gpo.Id -Properties gPCMachineExtensionNames, versionNumber -ErrorAction SilentlyContinue
            if (-not $adGpo) { Start-Sleep -Seconds 2 }
        }
        if (-not $adGpo) {
            throw "GPO AD container not found for GUID $($gpo.Id) on PDC $pdcHost. Confirm the GPO was created and AD replication completed."
        }

        $newExt = Merge-GPCExtensionGuid -Current $adGpo.gPCMachineExtensionNames -CseGuid $secCse -ToolGuid $secTool
        $newVer = Step-GPOVersion -CurrentVersion $adGpo.versionNumber

        Write-Verbose "Registering Security CSE and bumping version to $newVer at $($adGpo.DistinguishedName) on $pdcHost"
        Set-ADObject -Server $pdcHost -Identity $adGpo.DistinguishedName -Replace @{
            gPCMachineExtensionNames = $newExt
            versionNumber            = [int]$newVer
        }

        # --- 4. Keep SYSVOL's gpt.ini in sync with the AD version number. ---
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

        Write-Host "Audit GPO '$Name' created and configured ($($gpo.Id))." -ForegroundColor Green
        Write-Host "The GPO was NOT linked. Don't forget to review and link the GPO." -ForegroundColor Green

        return $gpo
    } catch {
        try { Remove-GPO -Guid $gpo.Id -Domain $domainFqdn -ErrorAction SilentlyContinue } catch {}
        throw "Failed to configure GPO '$Name': $($_.Exception.Message)"
    }
}