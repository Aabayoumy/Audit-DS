# Create global variable OutputPath
$Global:DomainName = (Get-ADDomain).Name
$Global:TodayDate = Get-Date -Format "dd-MMM-yyyy"
$Global:OutputPath = "c:\$DomainName"
# Create the directory if it doesn't exist

# Read ignored DCs from JSON config file
try {
    $IgnoredDCs = Get-Content -Path "$PSScriptRoot\AuditDS.json" -Raw | ConvertFrom-Json
    $Global:IgnoredDCs = $IgnoredDCs
    Write-Host "Ignored DCs loaded from AuditDS.json"
} catch {
    Write-Warning "Could not load ignored DCs from AuditDS.json. $($_.Exception.Message)"
    $Global:IgnoredDCs = @()
}

# Private function to check for administrative privileges
function _AssertAdminPrivileges {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Throw "This script requires administrative privileges to run. Please re-run PowerShell as Administrator."
        exit 1 # Terminate the script immediately
    }
}

function Export-NTLMEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-NTLM here
        [int]$MaxEvents = 10000
    )
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\NTLM-$($Global:TodayDate)\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    foreach ($DC in (Get-ADDomainController -Filter *).HostName){
        $OutputFile = "$OutputPath\$($DC).csv"
        Write-Host "[$($DC)] Searching log" 
        $Events = Get-WinEvent -ComputerName $DC -Logname security -MaxEvents $MaxEvents  -FilterXPath "Event[System[(EventID=4624)]]and (Event[EventData[Data[@Name='LmPackageName']='NTLM V2']] or Event[EventData[Data[@Name='LmPackageName']='NTLM V1']])" | Select-Object `
        @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
        @{Label='UserName';Expression={$_.Properties[5].Value}},
        @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
        @{Label='WorkstationIP';Expression={$_.Properties[18].Value}},
        @{Label='LogonType';Expression={$_.properties[8].value}},
        @{Label='LmPackageName';Expression={$_.properties[14].value}},
        @{Label='ImpersonationLevel';Expression={$_.properties[20].value}}
        $Events | Export-Csv $OutputFile -NoTypeInformation
        # Filter for NTLM V1 events excluding ANONYMOUS LOGON
        $NtlmV1Events = $Events | Where-Object { $_.LmPackageName -eq 'NTLM V1' -and $_.UserName -ne 'ANONYMOUS LOGON' }
        $NtlmV1Count = $NtlmV1Events.Count
        # Update Write-Host to include the count
        Write-Host "[$($DC)] $NtlmV1Count NTLMv1 Events"
    }
}

function Export-LDAPEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-LDAP here
        [int]$MaxEvents = 10000
    )
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\LDAP-$($Global:TodayDate)\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    # Implementation for Audit-LDAP
    Write-Host "Audit-LDAP command executed."
}

# Generate DC list
function Export-ADInfo {
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\ADInfo-$($Global:TodayDate)"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $Forest=Get-ADForest ; $ADDomain=Get-ADDomain ; $DN=($ADDomain.DistinguishedName)
    $null = Start-Transcript -Path "$OutputPath\transcript.txt"
    ($Forest | Select-Object Name, RootDomain,Domains, ForestMode, SchemaMaster, DomainNamingMaster, Sites | Out-String).Trim() > "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt"
    (Get-ADReplicationSubnet -Filter * | Select-Object Name, Site | Sort-Object Site | Format-Table | Out-String).Trim() > "$OutputPath\Subnets.txt"
    Add-Content -Path "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt" -Value "*`r`n#Domain $($ADDomain.DNSRoot)"
    ($ADDomain | Select-Object NetBIOSName, DNSRoot, DomainMode, PDCEmulator, InfrastructureMaster, RIDMaster | Out-String).Trim() >> "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt"
    Add-Content -Path "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt" -Value "`r`n"
    (Get-ADDomainController -Filter *  | Select-Object HostName, IsReadOnly, OperatingSystem, IPv4Address, Site | Sort-Object Site | Format-Table | Out-String).Trim() >> "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt"
    Add-Content -Path "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt" -Value "`r`n-IPConfig"
    (ipconfig /all  | Out-String).Trim() >> "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt"
    repadmin /showrepl *   /csv > "$OutputPath\showrepl.csv"
    # repadmin /showrepl $(${Env:ComputerName}) /csv > "$OutputPath\$(${Env:ComputerName})_showrepl.csv"
    # repadmin /replsummary  /csv > "$OutputPath\$(${Env:ComputerName})_replsummary.csv"
    Gpresult /h "$($OutputPath)\$($env:computername)_GPResult.html"
    Auditpol /get /category:* > "$($OutputPath)\$($env:computername)_Audit.txt"
    (Get-ADForest -Current LoggedOnUser).Domains | %{ Get-ADDefaultDomainPasswordPolicy -Identity $_ } > "$OutputPath\DomainPasswordPolicy.txt"
    nltest /DOMAIN_TRUSTS  > "$OutputPath\Trust.txt"
    Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Select-Object samaccountname,enabled,DistinguishedName > "$OutputPath\users-password-never-expires.txt"
    Get-ADUser -Filter {(adminCount -ne 0 ) -and (serviceprincipalname -like "*") }  -Property samaccountname, DistinguishedName, serviceprincipalname, enabled | Select-Object samaccountname, DistinguishedName, serviceprincipalname, enabled > "$OutputPath\users-with-spn.txt" # users with spn
    Get-ADUser -Filter { TrustedForDelegation -eq $True } -Property DistinguishedName, ServicePrincipalName, TrustedForDelegation | Select-Object DistinguishedName, ServicePrincipalName, TrustedForDelegation , enabled > "$OutputPath\users-with-unconstrained-delegation.txt" # users with  unconstrained delegation
    Get-ADComputer -Filter { (TrustedForDelegation -eq $True) -and (PrimaryGroupID -ne 516) } -Property DistinguishedName, ServicePrincipalName, TrustedForDelegation | Select-Object DistinguishedName, ServicePrincipalName, TrustedForDelegation , enabled > "$OutputPath\servers-with-unconstrained-delegation.txt" # servers with  unconstrained delegation
    Get-ACL "AD:\$DN" | Select-Object -ExpandProperty Access | Where-Object {($_.ObjectType -eq '89e95b76-444d-4c62-991a-0facbeda640c' -or $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')} | Select-Object IdentityReference > "$OutputPath\users-with-dcsync-privilege.txt" # users withdcsync rights
    $DaysInactive = 180
    $time = (Get-Date).Adddays(-($DaysInactive))
    Get-ADUser -Filter '(LastLogonTimestamp -lt $time)' -Properties enabled,PasswordLastSet,LastLogonTimestamp | Format-Table Name,enabled,PasswordLastSet,@{N="LastLogonTimestamp";E={[datetime]::FromFileTime($_.LastLogonTimestamp)}}  >  "$OutputPath\Inactive_Users.txt"
    Get-ADComputer -Filter { (LastLogonTimestamp -lt $time -or LastLogonTimestamp -notlike "*") } -Properties LastLogonTimestamp, WhenCreated, PasswordLastSet | Select-Object Name, WhenCreated, PasswordLastSet, @{N="LastLogonTimestamp";E={if ($_.LastLogonTimestamp) {[datetime]::FromFileTime($_.LastLogonTimestamp)} else {"Never"}}} > "$OutputPath\Inactive_Computers.txt"
    Get-ADUser "krbtgt" -Property Created, PasswordLastSet > "$OutputPath\$($ADDomain.DNSRoot)_krbtgt.txt"
    netsh advfirewall show allprofiles > "$OutputPath\Firewall_Profiles.txt"
    $null = Stop-Transcript
    Add-Type -As System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory( "$OutputPath", "$($OutputPath).zip" )
    If (Test-Path -Path "$($OutputPath).zip") { Remove-Item -Recurse -Force $OutputPath }
    Start-Process "$(Split-Path -parent $OutputPath)"
}



Export-ModuleMember -Function Export-NTLMEvents, Export-LDAPEvents, Export-ADInfo
