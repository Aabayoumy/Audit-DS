<#
.SYNOPSIS
Sets the maximum size for Security and Directory Service event logs on specified Domain Controllers.

.DESCRIPTION
This function retrieves all Domain Controllers (DCs) in the current domain, filters out any DCs listed in the ignored DCs configuration, and then sets the maximum size for the Security and 'Directory Service' event logs on the remaining DCs using the Limit-EventLog cmdlet. It defaults to 2GB but can be set to 2, 3, or 4 GB using the -Size parameter. After setting the limits, it displays a warning that the EventLog service needs to be restarted for the changes to take effect. Requires administrative privileges on the target DCs.

.PARAMETER Size
Specifies the maximum size for the event logs in Gigabytes (GB).
Valid values are 2, 3, or 4. Defaults to 2.

.EXAMPLE
PS C:\> Set-LogSize
Sets the Security and Directory Service log sizes to 2GB on all applicable Domain Controllers and warns the user to restart the EventLog service.

.EXAMPLE
PS C:\> Set-LogSize -Size 4
Sets the Security and Directory Service log sizes to 4GB on all applicable Domain Controllers and warns the user to restart the EventLog service.

.EXAMPLE
PS C:\> Set-LogSize -Verbose
Sets the log sizes to the default 2GB, provides detailed output about the operations being performed on each DC, and warns the user to restart the EventLog service.

.NOTES
- Requires the Active Directory PowerShell module.
- Requires administrative privileges on the target Domain Controllers to modify event log settings and restart services.
- The list of ignored DCs is retrieved using the internal _GetIgnoredDCs function.
#>
function Set-LogSize {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet(2, 3, 4)]
        [int]$Size = 2, # Default size in GB
        [Parameter(Mandatory = $false)]
        [string[]]$IgnoredDCs = @(), # Array of DC names to ignore
        [switch]$Help,
        [switch]$h
    )

    Begin {
        # Check for help parameters or any other parameters
        if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-Size', '-IgnoredDCs'))) {
            Write-Host "Sets the maximum size for Security and Directory Service event logs on domain controllers."
            Write-Host "-Size: Specifies the maximum log size in GB (Valid: 2, 3, or 4. Default: 2)."
            Write-Host "-IgnoredDCs: Specifies one or more Domain Controller names to ignore (e.g., 'DC1', 'DC2', 'DC3')."
            return
        }

        Write-Verbose "Starting Set-LogSize function."
        # Ensure running with elevated privileges (basic check)
        if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning "This script requires administrative privileges to modify event log settings and restart services on remote machines."
            # Consider adding a more robust check or forcing elevation if needed.
        }

        # Convert GB to Bytes for Limit-EventLog
        $maxSizeBytes = $Size * 1GB
        Write-Verbose "Target log size set to $($Size)GB ($($maxSizeBytes) bytes)."

        # Get all Domain Controllers using Get-ADDomainController
        try {
            # Using Get-ADDomainController with a filter to get all DCs
            $allDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
            Write-Verbose "Successfully retrieved all DCs using Get-ADDomainController: $($allDCs -join ', ')"
        }
        catch {
            Write-Error "Failed to retrieve Domain Controllers using Get-ADDomainController. Ensure the Active Directory module is available and you have permissions. Error: $($_.Exception.Message)"
            return
        }

        # Filter out ignored DCs
        $targetDCs = $allDCs | Where-Object { $_ -notin $ignoredDCs }
        Write-Verbose "Target DCs after filtering ignored ones: $($targetDCs -join ', ')"

        if (-not $targetDCs) {
            Write-Warning "No target Domain Controllers found after filtering."
            return
        }
    }

    Process {
        foreach ($dc in $targetDCs) {
            Write-Verbose "Processing Domain Controller: $dc"

            if ($PSCmdlet.ShouldProcess($dc, "Set Security & Directory Service Log Max Size to $($Size)GB")) {
                try {
                    Write-Verbose "Attempting to set log sizes on $dc..."
                    
                    # Set Security log size
                    Write-Verbose "Setting Security log max size on $dc to $($Size)GB"
                    Limit-EventLog -LogName Security -MaximumSize $maxSizeBytes -ComputerName $dc -ErrorAction Stop

                    # Set Directory Service log size
                    Write-Verbose "Setting Directory Service log max size on $dc to $($Size)GB"
                    Limit-EventLog -LogName 'Directory Service' -MaximumSize $maxSizeBytes -ComputerName $dc -ErrorAction Stop

                    Write-Host -ForegroundColor Green "Successfully updated log sizes on ${dc}."
                    Write-Host -ForegroundColor Green "The EventLog service on ${dc} must be restarted for the new log sizes to take effect."
                }
                catch {
                    Write-Error "Failed to process $dc. Error: $($_.Exception.Message)"
                    # Continue to the next DC
                }
            }
            else {
                Write-Warning "Skipped processing $dc due to -WhatIf parameter or user cancellation."
            }
        }
    }

    End {
        Write-Verbose "Set-LogSize function finished."
    }
}
