function New-AuditGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name = '_Audit-NTLM-Ldap',

        [Parameter(Mandatory = $false)]
        [string]$Domain,

        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-Name', '-Domain'))) {
        Write-Host 'Creates a new (unlinked) GPO that enables NTLM and LDAP auditing.'
        Write-Host '-Name: GPO display name (default: _Audit-NTLM-Ldap).'
        Write-Host '-Domain: Domain FQDN. If omitted, the current AD domain is used.'
        return
    }

    # Ensure the GroupPolicy module is available
    if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
        Write-Error "GroupPolicy module is required but not found. Install RSAT Group Policy Management features first."
        return
    }
    Import-Module GroupPolicy -ErrorAction Stop

    # Ensure the ActiveDirectory module is available
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        Write-Error "ActiveDirectory module is required but not found."
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $domainFqdn = $Domain
    if (-not $domainFqdn) {
        $domainFqdn = (Get-ADDomain).DNSRoot
    }

    # Create the GPO (not linked)
    Write-Verbose "Creating GPO '$Name' in domain $domainFqdn"
    if (Get-GPO -Name $Name -Domain $domainFqdn -ErrorAction SilentlyContinue) {
        Write-Error "A GPO named '$Name' already exists. Delete it or use a different -Name."
        return
    }
    try {
        $gpo = New-GPO -Name $Name -Domain $domainFqdn -ErrorAction Stop
    } catch {
        throw "Failed to create GPO '$Name': $($_.Exception.Message)"
    }
    Write-Host "GPO '$Name' created (not linked)." -ForegroundColor Cyan

    $guid = $gpo.Id

    try {
        # Network security: Restrict NTLM: Audit Incoming NTLM Traffic -> Enable auditing for all accounts (2)
        Set-GPRegistryValue -Guid $guid -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ValueName 'AuditReceivingNTLMTraffic' -Type DWord -Value 2 -ErrorAction Stop

        # Network security: Restrict NTLM: Audit NTLM authentication in this domain -> Enable all (3)
        Set-GPRegistryValue -Guid $guid -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'AuditNtlmAuthenticationInDomain' -Type DWord -Value 3 -ErrorAction Stop

        # Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers -> Audit all (1)
        Set-GPRegistryValue -Guid $guid -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ValueName 'RestrictSendingNTLMTraffic' -Type DWord -Value 1 -ErrorAction Stop

        # Event Log Service > Security log maximum size (KB) -> 2 GB (2097152 KB)
        Set-GPRegistryValue -Guid $guid -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -ValueName 'MaxSize' -Type DWord -Value 2097152 -ErrorAction Stop
    } catch {
        throw "Failed to apply registry-based settings to GPO '$Name': $($_.Exception.Message)"
    }

    # Write the LDAP Interface Events registry preference (GPP) directly to SYSVOL.
    # No GroupPolicy module cmdlet supports GPP registry items, so we author Registry.xml.
    try {
        $prefDir = "\\$domainFqdn\SysVol\$domainFqdn\Policies\{$guid}\Machine\Preferences\Registry"
        $registryXml = Join-Path -Path $prefDir -ChildPath 'Registry.xml'

        if (-not (Test-Path $prefDir)) {
            New-Item -ItemType Directory -Path $prefDir -Force | Out-Null
        }

        $changed   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $uid       = '{' + [Guid]::NewGuid().ToString().ToUpper() + '}'

        $item = @"
<Registry clsid="{9CD4B2F4-923D-47f9-A542-DE1B8A96B7FE}" name="16 LDAP Interface Events" status="S" image="1" changed="$changed" uid="$uid">
    <Properties action="U" displayDecimal="1" defaultHidden="0" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" valueName="16 LDAP Interface Events" value="2" type="REG_DWORD"/>
</Registry>
"@

        if (Test-Path $registryXml) {
            $content = [System.IO.File]::ReadAllText($registryXml)
            $content = $content.Replace('</RegistrySettings>', $item + "`r`n" + '</RegistrySettings>')
            [System.IO.File]::WriteAllText($registryXml, $content, (New-Object System.Text.UTF8Encoding($false)))
        } else {
            $fullXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{9CD4B2F4-923D-47f9-A542-DE1B8A96B7FE}">
$item</RegistrySettings>
"@
            [System.IO.File]::WriteAllText($registryXml, $fullXml, (New-Object System.Text.UTF8Encoding($false)))
        }

        # Bump the GPO computer version so clients re-apply the GPP item we wrote directly to SYSVOL.
        $gptIni  = "\\$domainFqdn\SysVol\$domainFqdn\Policies\{$guid}\GPT.INI"
        $domainDn = (Get-ADDomain).DistinguishedName
        if ((Test-Path $gptIni) -and $domainDn) {
            $gptContent = [System.IO.File]::ReadAllText($gptIni)
            $m = [regex]::Match($gptContent, '(?m)^Version=(\d+)')
            if ($m.Success) {
                $oldVersion   = [int]$m.Groups[1].Value
                $userVersion  = [int]((($oldVersion -shr 16) -band 0xFFFF))
                [int]$computerVersion = $oldVersion -band 0xFFFF
                $computerVersion++
                $newVersion = (($userVersion -shl 16) -bor ($computerVersion -band 0xFFFF))
                $gptContent = [regex]::Replace($gptContent, '(?m)^Version=\d+', "Version=$newVersion")
                [System.IO.File]::WriteAllText($gptIni, $gptContent, (New-Object System.Text.UTF8Encoding($false)))
                Set-ADObject -Identity "CN={$guid},CN=Policies,CN=System,$domainDn" -Replace @{ versionNumber = $newVersion } -ErrorAction SilentlyContinue
                Write-Verbose "Bumped GPO version to $newVersion"
            }
        }
    } catch {
        Write-Warning "LDAP registry preference could not be written: $($_.Exception.Message)"
    }

    Write-Host "Audit settings applied to '$Name' (GUID: $guid)." -ForegroundColor Green
    Write-Host "The GPO was NOT linked. Don't forget to review and link the GPO." -ForegroundColor Green

    return $gpo
}