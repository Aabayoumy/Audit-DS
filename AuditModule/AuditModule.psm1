
# TODO:
# - separate each function on separate file under public folder 
# - add help to each function 


# Create global variable OutputPath
$Global:DomainName = (Get-ADDomain).Name
$Global:OutputPath = "c:\$DomainName"


# Private function to load ignored DCs from JSON
function _GetIgnoredDCs {
    param(
        
    )

    $IgnoredDCs = @() # Initialize as an empty array within the function scope
    try {
        $JsonPath = Join-Path -Path $PSScriptRoot  -ChildPath "AuditDS.json"
        # Check if the JSON file exists before trying to read it
        if (Test-Path -Path $JsonPath) {
            $IgnoredDCsObject = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json
            # Ensure the property exists before trying to access it
            if ($IgnoredDCsObject -and $IgnoredDCsObject.PSObject.Properties.Name -contains 'ignored-DCs') {
                $IgnoredDCs = $IgnoredDCsObject.'ignored-DCs'
                # Check if the array is not null and not empty
                if ($IgnoredDCs -and $IgnoredDCs.Count -gt 0) {
                    Write-Host "Ignoring the following DCs: $($IgnoredDCs -join ', ')"
                }
            } else {
                # Handle case where JSON is valid but doesn't contain 'ignored-DCs' or is empty/malformed
                # $IgnoredDCs is already @()
            }
        } else {
            Write-Warning "AuditDS.json not found at '$JsonPath'. No DCs will be ignored."
            # $IgnoredDCs is already @()
        }
    } catch {
        Write-Warning "Could not load ignored DCs from AuditDS.json. $($_.Exception.Message)"
        # $IgnoredDCs is already @()
    }
    # Return the array
    return $IgnoredDCs
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
    $OutputPath = "$Global:OutputPath\NTLM-$((Get-Date).ToString('ddMMMyy-HHmm'))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $IgnoredDCs =  _GetIgnoredDCs # Load ignored DCs
    foreach ($DC in (Get-ADDomainController -Filter *).HostName | Where-Object { $_ -notin $IgnoredDCs }){
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
    $OutputPath = "$Global:OutputPath\LDAP-$($((Get-Date).ToString('ddMMMyy-HHmm')))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $IgnoredDCs =  _GetIgnoredDCs # Load ignored DCs
    # Implementation for Audit-LDAP
    foreach ($DC in (Get-ADDomainController -Filter *).HostName | Where-Object { $_ -notin $IgnoredDCs }){
        $OutputFile = "$OutputPath\$($DC)_$((Get-Date).ToString('dd-MMMM-yyyy')).csv"
        $Events = Get-WinEvent -Logname "Directory Service" -FilterXPath "Event[System[(EventID=2889)]]" | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},   @{Label='SourceIP';Expression={$_.Properties[0].Value}},    @{Label='User';Expression={$_.Properties[1].Value}}
        $Events | Export-Csv $OutputFile -NoTypeInformation
    }
}
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

# Function to list Domain Controllers with specific details
function Get-DCs {
    [CmdletBinding()]
    param()

    # Retrieve and format DC information
    return (Get-ADDomainController -Filter * | Select-Object HostName, IsReadOnly, OperatingSystem, IPv4Address, Site | Sort-Object HostName | Format-Table | Out-String).Trim()
}

# Function to export administrative users based on group membership and adminCount
function Export-AdminUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, HelpMessage="Path to export the CSV file.")]
        [string]$OutputPath
    )
    _AssertAdminPrivileges # Check for admin privileges
    # if OutputPath is not set, use $Global:OutputPath
    if (-not $OutputPath) {$OutputPath = "$Global:OutputPath"}

    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $OutputFile = "$OutputPath\AdminUsers-$($((Get-Date).ToString('ddMMMyy-HHmm'))).csv"
    # Ensure the Active Directory module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Active Directory module is not installed. Please install the RSAT tools."
        # Consider using 'return' instead of 'exit 1' within a module function
        return 
    }

    # List of administrative groups to check
    $AdminGroups = @(
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Account Operators",
        "Server Operators",
        "Print Operators",
        "Backup Operators"
    )

    # Hashtable to store unique admin users found
    $AdminUsers = @{}

    Write-Host "Searching for admin users in specified groups..."

    foreach ($GroupName in $AdminGroups) {
        try {
            Write-Host "Checking group: $GroupName"
            # Ensure we only process user objects
            $GroupMembers = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }

            foreach ($Member in $GroupMembers) {
                # Check if user is already processed to avoid redundant lookups
                if (-not $AdminUsers.ContainsKey($Member.SamAccountName)) {
                    try {
                        # Add PasswordNeverExpires to the properties requested
                        $User = Get-ADUser -Identity $Member.SamAccountName -Properties adminCount, pwdLastSet, Enabled, LastLogonTimestamp, PasswordNeverExpires -ErrorAction Stop

                        # Check if adminCount is 1
                        if ($User.adminCount -eq 1) {
                            # Convert LastLogonTimestamp from FileTime to DateTime
                            $LastLogonDate = if ($User.LastLogonTimestamp -ne $null -and $User.LastLogonTimestamp -ne 0) {
                                [DateTime]::FromFileTime($User.LastLogonTimestamp)
                            } else {
                                $null # Or use a placeholder like 'Never'
                            }

                            # Convert PwdLastSet from ticks to DateTime (UTC based on AD standard)
                            $PwdLastSetDate = if ($User.pwdLastSet -ne $null -and $User.pwdLastSet -ne 0) {
                                 [datetime]::FromFileTimeUtc((Get-Date -Date "1601-01-01 00:00:00Z").AddTicks($User.pwdLastSet).Ticks)
                            } else {
                                $null # Or use a placeholder like 'Never' or 'Password Never Expires'
                            }

                            # Add PasswordNeverExpires to the PSCustomObject
                            $AdminUsers[$User.SamAccountName] = [PSCustomObject]@{
                                SamAccountName      = $User.SamAccountName
                                PwdLastSet          = $PwdLastSetDate
                                Enabled             = $User.Enabled
                                LastLogonTimestamp  = $LastLogonDate
                                PasswordNeverExpires = $User.PasswordNeverExpires # Added attribute
                                AdminCount          = $User.adminCount # Included for verification
                                MemberOfAdminGroups = "" # Placeholder, will be populated below
                            }

                            # Determine which admin groups the user is a member of from the target list
                            # Use try-catch for Get-ADPrincipalGroupMembership as it can fail if user not found or permissions issue
                            try {
                                $userAdminGroups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName -ErrorAction Stop | Where-Object { $AdminGroups -contains $_.Name } | Select-Object -ExpandProperty Name
                                $AdminUsers[$User.SamAccountName].MemberOfAdminGroups = $userAdminGroups -join ", "
                                # Write-Host "  Found admin user: $($User.SamAccountName) (Member of: $($AdminUsers[$User.SamAccountName].MemberOfAdminGroups))" -ForegroundColor Green
                            } catch {
                                Write-Warning "Could not retrieve group membership for user '$($User.SamAccountName)': $($_.Exception.Message)"
                                # Still add the user but indicate group membership check failed
                                $AdminUsers[$User.SamAccountName].MemberOfAdminGroups = "Error checking groups"
                                Write-Host "  Found admin user: $($User.SamAccountName) (Group check failed)" -ForegroundColor Yellow
                            }
                        }
                    } catch {
                        # Catch errors getting user details (e.g., permissions, user deleted between steps)
                        Write-Warning "Could not retrieve details for user '$($Member.SamAccountName)': $($_.Exception.Message)"
                    }
                }
            }
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "Group '$GroupName' not found or could not be accessed."
        } catch {
            # Catch other errors during group member retrieval
            Write-Warning "An error occurred while processing group '$GroupName': $($_.Exception.Message)"
        }
    }

    # Export the collected users to CSV
    if ($AdminUsers.Count -gt 0) {
        try {
            Write-Host "Exporting $($AdminUsers.Count) admin users to $OutputFile..." # Corrected variable name from $ExportPath
            # Add PasswordNeverExpires to the Select-Object list for export
            $AdminUsers.Values | Select-Object SamAccountName, PwdLastSet, Enabled, LastLogonTimestamp, PasswordNeverExpires, MemberOfAdminGroups | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            # Write-Host "Export complete: $OutputFile" -ForegroundColor Green # Corrected variable name from $ExportPath
        } catch {
            Write-Error "Failed to export CSV file to '$OutputFile': $($_.Exception.Message)" # Corrected variable name from $ExportPath
        }
    } else {
        Write-Host "No admin users found matching the criteria (member of specified groups and adminCount=1)." -ForegroundColor Yellow
    }
}

Export-ModuleMember -Function Export-NTLMEvents, Export-LDAPEvents, Export-ADInfo, Get-DCs, Export-AdminUsers
