# Internal: maps GPO backup GUIDs to display names. Returns SortedList of [DisplayName -> GUID].
function MapGuidsToGpoNames {
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
