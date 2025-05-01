function Export-ADInfo {
    [CmdletBinding()]
    param (
        [switch]$zip
    )
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\ADInfo-$($((Get-Date).ToString('ddMMMyy-HHmm')))"
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
    # TODO:
    # - export users states for : azure sso , MSOL's and azureadkerberos
    # - export out of support OS computers with parameter --all for all Computers

    netsh advfirewall show allprofiles > "$OutputPath\Firewall_Profiles.txt"
    Export-AdminUsers -OutputPath $OutputPath
    $null = Stop-Transcript
    if ($zip.IsPresent) {
        Add-Type -As System.IO.Compression.FileSystem
        If (Test-Path -Path "$($OutputPath).zip") { Remove-Item  -Force "$($OutputPath).zip" }
        [IO.Compression.ZipFile]::CreateFromDirectory( "$($OutputPath)", "$($OutputPath).zip" )
        If (Test-Path -Path "$($OutputPath).zip") { Remove-Item -Recurse -Force $OutputPath }
    }
    Start-Process "$(Split-Path -parent $OutputPath)"
}
