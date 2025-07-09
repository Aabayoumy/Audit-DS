# Function to export administrative users based on group membership and adminCount
# Function to export administrative users based on group membership and adminCount
function Export-AdminUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, HelpMessage="Path to export the CSV file.")]
        [string]$OutputPath,
        [switch]$Help,
        [switch]$h
    )

    # Check for help parameters or any other parameters
    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-OutputPath'))) {
        Write-Host "Exports administrative users based on group membership and adminCount."
        Write-Host "-OutputPath: Path to export the CSV file."
        return
    }

    AssertAdminPrivileges # Check for admin privileges
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

    Write-Verbose "Searching for admin users in specified groups..."

    foreach ($GroupName in $AdminGroups) {
        try {
            Write-Verbose "Checking group: $GroupName"
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

                            # Convert PwdLastSet from FileTime to DateTime
                            $PwdLastSetDate = if ($User.pwdLastSet -ne $null -and $User.pwdLastSet -ne 0) {
                                [DateTime]::FromFileTime($User.pwdLastSet)
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
                                # Write-Verbose "  Found admin user: $($User.SamAccountName) (Member of: $($AdminUsers[$User.SamAccountName].MemberOfAdminGroups))"
                            } catch {
                                Write-Verbose "Could not retrieve group membership for user '$($User.SamAccountName)': $($_.Exception.Message)"
                                # Still add the user but indicate group membership check failed
                                $AdminUsers[$User.SamAccountName].MemberOfAdminGroups = "Error checking groups"
                                Write-Verbose "  Found admin user: $($User.SamAccountName) (Group check failed)"
                            }
                        }
                    } catch {
                        # Catch errors getting user details (e.g., permissions, user deleted between steps)
                        Write-Verbose "Could not retrieve details for user '$($Member.SamAccountName)': $($_.Exception.Message)"
                    }
                }
            }
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Verbose "Group '$GroupName' not found or could not be accessed."
        } catch {
            # Catch other errors during group member retrieval
            Write-Verbose "An error occurred while processing group '$GroupName': $($_.Exception.Message)"
        }
    }

    # Export the collected users to CSV
    if ($AdminUsers.Count -gt 0) {
        try {
            Write-Verbose "Exporting $($AdminUsers.Count) admin users to $OutputFile..." # Corrected variable name from $ExportPath
            # Add PasswordNeverExpires to the Select-Object list for export
            $AdminUsers.Values | Select-Object SamAccountName, PwdLastSet, Enabled, LastLogonTimestamp, PasswordNeverExpires, MemberOfAdminGroups | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            # Write-Verbose "Export complete: $OutputFile" # Corrected variable name from $ExportPath
        } catch {
            Write-Error "Failed to export CSV file to '$OutputFile': $($_.Exception.Message)" # Corrected variable name from $ExportPath
        }
    } else {
        Write-Verbose "No admin users found matching the criteria (member of specified groups and adminCount=1)."
    }
}
