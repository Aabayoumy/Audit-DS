<#
.SYNOPSIS
Sets the maximum size for Security and Directory Service event logs on specified Domain Controllers.

.DESCRIPTION
This function retrieves all Domain Controllers (DCs) in the current domain, filters out any DCs listed in the ignored DCs configuration, and then sets the maximum size for the Security and 'Directory Service' event logs on the remaining DCs using the Limit-EventLog cmdlet. It defaults to 2GB but can be set to 2, 3, or 4 GB using the -Size parameter. After setting the limits, it restarts the EventLog service on each targeted DC. Requires administrative privileges on the target DCs.

.PARAMETER Size
Specifies the maximum size for the event logs in Gigabytes (GB).
Valid values are 2, 3, or 4. Defaults to 2.

.EXAMPLE
PS C:\> Set-LogSize
Sets the Security and Directory Service log sizes to 2GB on all applicable Domain Controllers and restarts the EventLog service.

.EXAMPLE
PS C:\> Set-LogSize -Size 4
Sets the Security and Directory Service log sizes to 4GB on all applicable Domain Controllers and restarts the EventLog service.

.EXAMPLE
PS C:\> Set-LogSize -Verbose
Sets the log sizes to the default 2GB and provides detailed output about the operations being performed on each DC.

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
        [int]$Size = 2 # Default size in GB
    )

    Begin {
        Write-Verbose "Starting Set-LogSize function."
        # Ensure running with elevated privileges (basic check)
        if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning "This script requires administrative privileges to modify event log settings and restart services on remote machines."
            # Consider adding a more robust check or forcing elevation if needed.
        }

        # Convert GB to Bytes for Limit-EventLog
        $maxSizeBytes = $Size * 1GB
        Write-Verbose "Target log size set to $($Size)GB ($($maxSizeBytes) bytes)."

        # Get Ignored DCs using the private function (assuming it's accessible within the module scope)
        try {
            # Ensure the private function is available in the session state
            if (-not (Get-Command _GetIgnoredDCs -ErrorAction SilentlyContinue)) {
                 Write-Error "_GetIgnoredDCs function not found. Ensure the module is loaded correctly."
                 return
            }
            $ignoredDCs = _GetIgnoredDCs # Calling the private function
            Write-Verbose "Successfully retrieved ignored DCs: $($ignoredDCs -join ', ')"
        }
        catch {
            Write-Error "Failed to retrieve ignored DCs using _GetIgnoredDCs. Error: $($_.Exception.Message)"
            # Decide how to proceed: stop or continue without ignoring? Stopping is safer.
            return
        }

        # Get all Domain Controllers
        try {
            # Ensure the Get-DCs function is available
             if (-not (Get-Command Get-DCs -ErrorAction SilentlyContinue)) {
                 Write-Error "Get-DCs function not found. Ensure the module is loaded correctly."
                 return
            }
            # Assuming Get-DCs function exists and returns computer names or objects with a Name property
            $allDCs = Get-DCs | Select-Object -ExpandProperty Name # Adjust property name if needed
            Write-Verbose "Successfully retrieved all DCs: $($allDCs -join ', ')"
        }
        catch {
            Write-Error "Failed to retrieve Domain Controllers using Get-DCs. Ensure the Active Directory module is available and you have permissions. Error: $($_.Exception.Message)"
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

            if ($PSCmdlet.ShouldProcess($dc, "Set Security & Directory Service Log Max Size to $($Size)GB and Restart EventLog Service")) {
                try {
                    Write-Verbose "Attempting to set log sizes and restart EventLog service on $dc..."

                    # Set Security log size
                    Write-Verbose "Setting Security log max size on $dc to $($Size)GB"
                    Limit-EventLog -LogName Security -MaximumSize $maxSizeBytes -ComputerName $dc -ErrorAction Stop

                    # Set Directory Service log size
                    Write-Verbose "Setting Directory Service log max size on $dc to $($Size)GB"
                    Limit-EventLog -LogName 'Directory Service' -MaximumSize $maxSizeBytes -ComputerName $dc -ErrorAction Stop

                    # Restart EventLog service
                    Write-Verbose "Restarting EventLog service on $dc"
                    Restart-Service -Name EventLog -ComputerName $dc -Force -ErrorAction Stop

                    Write-Host "Successfully updated log sizes and restarted EventLog service on $dc."
                }
                catch {
                    Write-Error "Failed to process $dc. Error: $($_.Exception.Message)"
                    # Continue to the next DC, as the original script did
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
