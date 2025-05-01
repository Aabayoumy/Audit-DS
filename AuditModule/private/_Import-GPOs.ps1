function Import-GPOs {

    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [String]
        $GpoBackupPath

    )

    process {
        # Ensure the required module function is available
        if (-not (Get-Command MapGuidsToGpoNames -ErrorAction SilentlyContinue)) {
            Write-Error "Required private function 'MapGuidsToGpoNames' not found. Ensure it is loaded by the module."
            return
        }

        # Ensure the AD module is available
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
             Write-Error "Active Directory PowerShell module is required but not found."
             return
        }
        Import-Module ActiveDirectory -ErrorAction Stop

        # Map GPO Names to GUIDs
        Write-Verbose "Mapping GPO names to GUIDs in backup path: $GpoBackupPath"
        $GpoMap = MapGuidsToGpoNames -RootDir $GpoBackupPath
        if (-not $GpoMap -or $GpoMap.Count -eq 0) {
            Write-Error "No GPOs found or mapped in the backup path: $GpoBackupPath"
            return
        }

        Write-Host "Preparing to import the following GPOs:" -ForegroundColor Cyan
        Write-Host
        $GpoMap.Keys | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
        # Import GPOs
        Write-Host "Starting GPO import process..." -ForegroundColor Green
        $GpoMap.Keys | ForEach-Object {
            $gpoDisplayName = $_
            $guid = $GpoMap[$gpoDisplayName]

            Write-Host "Importing '$gpoDisplayName' (GUID: $guid) as '$gpoDisplayName'" -ForegroundColor Cyan
            if ($PSCmdlet.ShouldProcess($gpoDisplayName, "Import GPO from Backup ID $guid")) {
                try {
                    Import-GPO -BackupId $guid -Path $GpoBackupPath -TargetName $gpoDisplayName -CreateIfNeeded -ErrorAction Stop
                    Write-Verbose "Successfully imported '$gpoDisplayName'"
                } catch {
                    Write-Error "Failed to import GPO '$gpoDisplayName' (Backup ID: $guid): $($_.Exception.Message)"
                    # Continue with the next GPO
                }
            }
        }

        Write-Host "GPO import process completed." -ForegroundColor Green
    }
}
