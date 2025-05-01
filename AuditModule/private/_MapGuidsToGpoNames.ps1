function MapGuidsToGpoNames {
<#
.SYNOPSIS
Internal function to map GUIDs in a GPO backup to GPO display names.

.DESCRIPTION
Reads GPO backup directories to find "backup.xml" files, extracts the display name and GUID,
and returns a SortedList mapping display names to GUIDs.

.PARAMETER RootDir
Path to the directory containing one or more GPO backups.

.EXAMPLE
$gpoMap = MapGuidsToGpoNames -RootDir "C:\Path\To\GPO\Backups"
$gpoMap["My GPO Name"] # Returns the GUID for "My GPO Name"

.OUTPUTS
System.Collections.SortedList
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [String]
        $RootDir
    )

    process {
        if (-not (Test-Path -Path $RootDir -PathType Container)) {
            Write-Error "RootDir path '$RootDir' does not exist or is not a directory."
            return
        }

        $results = New-Object System.Collections.SortedList
        Get-ChildItem -Path $RootDir -Recurse -Include backup.xml | ForEach-Object {
            try {
                $guid = $_.Directory.Name
                $backupXmlPath = $_.FullName
                $xmlContent = Get-Content -Path $backupXmlPath -Raw
                $displayName = ([xml]$xmlContent).GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
                if (-not [string]::IsNullOrWhiteSpace($displayName) -and -not $results.ContainsKey($displayName)) {
                     $results.Add($displayName, $guid)
                } else {
                    Write-Warning "Could not add GPO from '$($_.Directory.FullName)'. Duplicate or empty display name found."
                }
            } catch {
                 Write-Warning "Error processing backup file '$($_.FullName)': $($_.Exception.Message)"
            }
        }

        return $results
    }
}
