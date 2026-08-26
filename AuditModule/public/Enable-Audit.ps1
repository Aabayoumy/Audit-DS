function Enable-Audit {
    param(
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help'))) {
        Write-Host "Imports GPO settings to enable auditing."
        return
    }

    Write-Verbose "Starting GPO import process."
    try {
        Import-GPOs -GpoBackupPath $PSScriptRoot\GPO
        Write-Host "GPO import process completed, Don't Forget to review and link GPO" -ForegroundColor Green
    } catch {
        Write-Error "An error occurred during the GPO import process: $($_.Exception.Message)"
    }
}
