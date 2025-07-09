function Export-ADInfo {
    [CmdletBinding()]
    param (
        [switch]$zip,
        [switch]$Help,
        [switch]$h
    )

    # Check for help parameters or any other parameters
    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-zip'))) {
        Write-Host "Exports comprehensive Active Directory information to files."
        Write-Host "-zip: Compresses output files into a zip archive."
        return
    }

    AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\ADInfo-$($((Get-Date).ToString('ddMMMyy-HHmm')))"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $Forest=Get-ADForest ; $ADDomain=Get-ADDomain ; $DN=($ADDomain.DistinguishedName)
    $null = Start-Transcript -Path "$OutputPath\transcript.txt"
    $ForestData = ($Forest | Select-Object Name, RootDomain,Domains, ForestMode, SchemaMaster, DomainNamingMaster, Sites )
    ($ForestData | Out-String).Trim() > "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt"   

    $Subnets = (Get-ADReplicationSubnet -Filter * | Select-Object Name, Site | Sort-Object Site )
    $Subnets | Export-Csv -Path "$OutputPath\Subnets.csv" -NoTypeInformation

    # Pass-NotReq Users
    Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=32)" -Properties userAccountControl | Select-Object samaccountname,useraccountcontrol | Export-Csv -Path "$OutputPath\users-pass-notreq.csv" -NoTypeInformation

    Add-Content -Path "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt" -Value "*`r`n#Domain $($ADDomain.DNSRoot)"
    ($ADDomain | Select-Object NetBIOSName, DNSRoot, DomainMode, PDCEmulator, InfrastructureMaster, RIDMaster | Out-String).Trim() >> "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt"
    Add-Content -Path "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt" -Value "`r`n"
    (Get-ADDomainController -Filter *  | Select-Object HostName, IsReadOnly, OperatingSystem, IPv4Address, Site | Sort-Object Site | Format-Table | Out-String).Trim() >> "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt"
    Add-Content -Path "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt" -Value "`r`n-IPConfig"
    (ipconfig /all  | Out-String).Trim() >> "$OutputPath\_ADInfo_$($ADDomain.DNSRoot).txt"
    repadmin /showrepl *   /csv > "$OutputPath\showrepl.csv"
    Gpresult /h "$($OutputPath)\$($env:computername)_GPResult.html"
    Auditpol /get /category:* > "$($OutputPath)\$($env:computername)_Audit.txt"
    (Get-ADForest -Current LoggedOnUser).Domains | %{ Get-ADDefaultDomainPasswordPolicy -Identity $_ } | Export-Csv -Path "$OutputPath\DomainPasswordPolicy.csv" -NoTypeInformation
    nltest /DOMAIN_TRUSTS  > "$OutputPath\Trust.txt"
    Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Select-Object samaccountname,enabled,DistinguishedName | Export-Csv -Path "$OutputPath\users-password-never-expires.csv" -NoTypeInformation
    Get-ADUser -Filter {(adminCount -ne 0 ) -and (serviceprincipalname -like "*") }  -Property samaccountname, DistinguishedName, serviceprincipalname, enabled | Select-Object samaccountname, DistinguishedName, serviceprincipalname, enabled | Export-Csv -Path "$OutputPath\users-with-spn.csv" -NoTypeInformation # users with spn
    Get-ADUser -Filter { TrustedForDelegation -eq $True } -Property DistinguishedName, ServicePrincipalName, TrustedForDelegation | Select-Object DistinguishedName, ServicePrincipalName, TrustedForDelegation , enabled | Export-Csv -Path "$OutputPath\users-with-unconstrained-delegation.csv" -NoTypeInformation # users with  unconstrained delegation
    Get-ADComputer -Filter { (TrustedForDelegation -eq $True) -and (PrimaryGroupID -ne 516) } -Property DistinguishedName, ServicePrincipalName, TrustedForDelegation | Select-Object DistinguishedName, ServicePrincipalName, TrustedForDelegation , enabled | Export-Csv -Path "$OutputPath\servers-with-unconstrained-delegation.csv" -NoTypeInformation # servers with  unconstrained delegation
    Get-ACL "AD:\$DN" | Select-Object -ExpandProperty Access | Where-Object {($_.ObjectType -eq '89e95b76-444d-4c62-991a-0facbeda640c' -or $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')} | Select-Object IdentityReference > "$OutputPath\users-with-dcsync-privilege.txt" # users withdcsync rights
    $DaysInactive = 180
    $time = (Get-Date).Adddays(-($DaysInactive))
    Get-ADUser -Filter '(LastLogonTimestamp -lt $time)' -Properties enabled,PasswordLastSet,LastLogonTimestamp | Select-Object Name,enabled,PasswordLastSet,@{N="LastLogonTimestamp";E={[datetime]::FromFileTime($_.LastLogonTimestamp)}} | Export-Csv -Path "$OutputPath\Inactive_Users.csv" -NoTypeInformation

    Get-ADComputer -Filter { (LastLogonTimestamp -lt $time -or LastLogonTimestamp -notlike "*") } -Properties LastLogonTimestamp, WhenCreated, PasswordLastSet | Select-Object Name, WhenCreated, PasswordLastSet, @{N="LastLogonTimestamp";E={if ($_.LastLogonTimestamp) {[datetime]::FromFileTime($_.LastLogonTimestamp)} else {"Never"}}} | Export-Csv -Path "$OutputPath\Inactive_Computers.csv" -NoTypeInformation
    
    # Define the list of special user account patterns to check
    $SpecialUserPatterns = @(
        'krb*',
        'AZURE*',
        'MSOL*'
        # Add more patterns here if needed in the future
    )

    # Retrieve and export details for the specified special users
    $SpecialUsersData = foreach ($pattern in $SpecialUserPatterns) {
        Get-ADUser -Filter "samaccountname -like '$pattern'" -Properties Created, PasswordLastSet, Enabled | Select-Object Name, samaccountname, Created, PasswordLastSet, Enabled
    }
    $SpecialUsersData | Sort-Object samaccountname | Export-Csv -Path "$OutputPath\SpecialUsers.csv" -NoTypeInformation -Encoding UTF8

    netsh advfirewall show allprofiles > "$OutputPath\Firewall_Profiles.txt"
    Export-AdminUsers -OutputPath $OutputPath
    Export-ComputersOS -OutputPath $OutputPath
    $null = Stop-Transcript
    if ($zip.IsPresent) {
        Add-Type -As System.IO.Compression.FileSystem
        If (Test-Path -Path "$($OutputPath).zip") { Remove-Item  -Force "$($OutputPath).zip" }
        [IO.Compression.ZipFile]::CreateFromDirectory( "$($OutputPath)", "$($OutputPath).zip" )
        If (Test-Path -Path "$($OutputPath).zip") { Remove-Item -Recurse -Force $OutputPath }
    }
    Start-Process "$(Split-Path -parent $OutputPath)"
}
