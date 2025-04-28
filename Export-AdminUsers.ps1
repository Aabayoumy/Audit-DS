<#
.SYNOPSIS
Exports administrative users based on group membership and adminCount attribute.

.DESCRIPTION
This script identifies users who are members of specified administrative groups
and have the adminCount attribute set to 1. It exports their SamAccountName,
pwdLastSet, Enabled status, and LastLogonTimestamp to a CSV file.

.NOTES
Requires the Active Directory PowerShell module.
Run this script with appropriate permissions to query Active Directory.
#>
param(
    [Parameter(Mandatory=$false, HelpMessage="Path to export the CSV file.")]
    [string]$ExportPath = ".\AdminUsersExport.csv"
)

# Ensure the Active Directory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory module is not installed. Please install the RSAT tools."
    exit 1
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
        $GroupMembers = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }

        foreach ($Member in $GroupMembers) {
            # Check if user is already processed
            if (-not $AdminUsers.ContainsKey($Member.SamAccountName)) {
                try {
                    $User = Get-ADUser -Identity $Member.SamAccountName -Properties adminCount, pwdLastSet, Enabled, LastLogonTimestamp -ErrorAction Stop

                    # Check if adminCount is 1
                    if ($User.adminCount -eq 1) {
                        # Convert LastLogonTimestamp from FileTime to DateTime
                        $LastLogonDate = if ($User.LastLogonTimestamp -ne $null -and $User.LastLogonTimestamp -ne 0) {
                            [DateTime]::FromFileTime($User.LastLogonTimestamp)
                        } else {
                            $null # Or use a placeholder like 'Never'
                        }

                        # Convert PwdLastSet from ticks to DateTime
                        $PwdLastSetDate = if ($User.pwdLastSet -ne $null -and $User.pwdLastSet -ne 0) {
                             [datetime]::FromFileTimeUtc((Get-Date -Date "1601-01-01 00:00:00Z").AddTicks($User.pwdLastSet).Ticks)
                        } else {
                            $null # Or use a placeholder like 'Never' or 'Password Never Expires'
                        }


                        $AdminUsers[$User.SamAccountName] = [PSCustomObject]@{
                            SamAccountName     = $User.SamAccountName
                            PwdLastSet         = $PwdLastSetDate
                            Enabled            = $User.Enabled
                            LastLogonTimestamp = $LastLogonDate
                            AdminCount         = $User.adminCount # Included for verification
                            MemberOfAdminGroups = "" # Placeholder, will be populated below
                        }

                        # Determine which admin groups the user is a member of from the target list
                        $userAdminGroups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName | Where-Object { $AdminGroups -contains $_.Name } | Select-Object -ExpandProperty Name
                        $AdminUsers[$User.SamAccountName].MemberOfAdminGroups = $userAdminGroups -join ", "

                        Write-Host "  Found admin user: $($User.SamAccountName) (Member of: $($AdminUsers[$User.SamAccountName].MemberOfAdminGroups))"
                    }
                } catch {
                    Write-Warning "Could not retrieve details for user '$($Member.SamAccountName)': $($_.Exception.Message)"
                }
            }
        }
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Warning "Group '$GroupName' not found or could not be accessed."
    } catch {
        Write-Warning "An error occurred while processing group '$GroupName': $($_.Exception.Message)"
    }
}

# Export the collected users to CSV
if ($AdminUsers.Count -gt 0) {
    Write-Host "Exporting $($AdminUsers.Count) admin users to $ExportPath..."
    $AdminUsers.Values | Select-Object SamAccountName, PwdLastSet, Enabled, LastLogonTimestamp, MemberOfAdminGroups | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "Export complete."
} else {
    Write-Host "No admin users found matching the criteria."
}
