function Enable-Audit {

        Write-Verbose "Starting GPO import process."
        Write-Host $PSScriptRoot
            try {
                # Call the internal function, splatting the parameters
                # Note: Assumes Import-GPOs is available in the module scope
                Import-GPOs -GpoBackupPath $PSScriptRoot\GPO
                Write-Verbose "Enable-Audit completed successfully."
            } catch {
                Write-Error "An error occurred during the GPO import process: $($_.Exception.Message)"
                # Re-throw the exception if needed or handle it
                # throw $_ # Uncomment to re-throw
            }
            Write-Host "GPO import process completed, Don't Forget to review and link GPO" -ForegroundColor Green
}
