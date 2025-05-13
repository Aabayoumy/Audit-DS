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
        [int]$Size = 2, # Default size in GB
        [switch]$Help,
        [switch]$h
    )

    Begin {
        # Check for help parameters or any other parameters
        if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-Size'))) {
            Write-Host "Sets the maximum size for Security and Directory Service event logs on domain controllers."
            Write-Host "-Size: Specifies the maximum log size in GB (Valid: 2, 3, or 4. Default: 2)."
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
        # Function to get service state using sc.exe
        Function Get-ServiceStateSC {
            param ($ComputerName, $ServiceName)
            $scOutput = ""
            $scError = ""
            $exitCode = -1
            # Generate unique temp file names
            $randomId = Get-Random
            $tempOutputFile = Join-Path $env:TEMP "sc_out_$($PID)_$($randomId).txt"
            $tempErrorFile = Join-Path $env:TEMP "sc_err_$($PID)_$($randomId).txt"

            try {
                # Ensure temp files don't exist from a previous failed run
                If (Test-Path $tempOutputFile) { Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue }
                If (Test-Path $tempErrorFile) { Remove-Item $tempErrorFile -Force -ErrorAction SilentlyContinue }

                $process = Start-Process sc.exe -ArgumentList "\\$ComputerName", "query", $ServiceName -Wait -NoNewWindow -PassThru -RedirectStandardOutput $tempOutputFile -RedirectStandardError $tempErrorFile
                $exitCode = $process.ExitCode
                
                if (Test-Path $tempOutputFile) {
                    $scOutput = Get-Content $tempOutputFile -Raw -ErrorAction SilentlyContinue
                }
                if (Test-Path $tempErrorFile) {
                    $scError = Get-Content $tempErrorFile -Raw -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Verbose "Exception running sc.exe query for $($ServiceName) on $($ComputerName): ${$_.Exception.Message}"
                return "ErrorInExecution"
            } finally {
                If (Test-Path $tempOutputFile) { Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue }
                If (Test-Path $tempErrorFile) { Remove-Item $tempErrorFile -Force -ErrorAction SilentlyContinue }
            }

            if ($exitCode -ne 0) {
                if ($scOutput -match "FAILED 1060" -or $scError -match "FAILED 1060") { # Service does not exist
                    Write-Verbose "Service $ServiceName not found on $ComputerName (SC FAILED 1060). Output: $scOutput Error: $scError"
                    return "NotFound"
                }
                if ($scError -match "FAILED 1722" -or $scOutput -match "FAILED 1722" -or $scError -match "RPC server is unavailable") { # The RPC server is unavailable.
                     Write-Verbose "RPC server unavailable for $ServiceName on $ComputerName (SC FAILED 1722 or similar). Output: $scOutput Error: $scError"
                     return "RpcError"
                }
                Write-Verbose "sc.exe query for $ServiceName on $ComputerName exited with code $exitCode. Output: $scOutput Error: $scError"
                return "QueryError" 
            }
            
            if ($scOutput -match "STATE\s+:\s+\d+\s+RUNNING") { return "Running" }
            if ($scOutput -match "STATE\s+:\s+\d+\s+STOPPED") { return "Stopped" }
            if ($scOutput -match "STATE\s+:\s+\d+\s+START_PENDING") { return "StartPending" }
            if ($scOutput -match "STATE\s+:\s+\d+\s+STOP_PENDING") { return "StopPending" }
            
            Write-Verbose "Could not determine service state for $ServiceName on $ComputerName from sc.exe output: $scOutput"
            return "Unknown"
        }

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

                    # Restart EventLog service using sc.exe
                    Write-Verbose "Attempting to restart EventLog service on ${dc} using sc.exe..."
                    $timeoutSeconds = 90 # Increased timeout for sc.exe operations, especially remote
                    $sleepInterval = 3   # Interval between state checks in seconds

                    # Check initial state
                    $currentState = Get-ServiceStateSC -ComputerName $dc -ServiceName 'EventLog'
                    Write-Verbose "Initial EventLog service state on ${dc}: $currentState"

                    if ($currentState -eq "NotFound") {
                        throw "EventLog service not found on ${dc} (queried via sc.exe)."
                    }
                    if ($currentState -eq "RpcError") {
                        throw "RPC error when querying EventLog service on ${dc}. The DC might be offline, firewall blocking RPC, or RPC services not running."
                    }
                    if ($currentState -eq "ErrorInExecution" -or $currentState -eq "QueryError") {
                        throw "Failed to query initial EventLog service state on ${dc} using sc.exe. State: $currentState"
                    }
                    
                    # Stop the service if it's running or in a pending state
                    if ($currentState -eq 'Running' -or $currentState -eq 'StartPending' -or $currentState -eq 'StopPending') {
                        Write-Verbose "Attempting to stop EventLog service on ${dc}..."
                        $process = Start-Process sc.exe -ArgumentList "\\$dc", "stop", "EventLog" -Wait -NoNewWindow -PassThru
                        $scStopExitCode = $process.ExitCode

                        # Exit code 0: Success.
                        # Exit code 1062: "The service has not been started." (already stopped).
                        if ($scStopExitCode -ne 0 -and $scStopExitCode -ne 1062) {
                            throw "sc.exe stop EventLog on ${dc} failed with exit code $scStopExitCode. Check permissions or sc.exe output manually if needed."
                        }
                        Write-Verbose "sc.exe stop command sent to EventLog on ${dc} (ExitCode: $scStopExitCode)."

                        Write-Verbose "Waiting for EventLog service to stop on ${dc}..."
                        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                        # Refresh state immediately after sending command before loop
                        $currentState = Get-ServiceStateSC -ComputerName $dc -ServiceName 'EventLog' 
                        while ($currentState -ne 'Stopped' -and $stopWatch.Elapsed.TotalSeconds -lt $timeoutSeconds) {
                            if ($currentState -eq "NotFound" -or $currentState -eq "RpcError" -or $currentState -eq "ErrorInExecution" -or $currentState -eq "QueryError") {
                                throw "Error querying EventLog service state on ${dc} while waiting for stop: $currentState. Last sc.exe stop exit code: $scStopExitCode"
                            }
                            Start-Sleep -Seconds $sleepInterval
                            $currentState = Get-ServiceStateSC -ComputerName $dc -ServiceName 'EventLog'
                            Write-Verbose "Waiting for stop... Current state: $currentState (Elapsed: $($stopWatch.Elapsed.ToString('hh\:mm\:ss')))"
                        }
                        $stopWatch.Stop()

                        if ($currentState -ne 'Stopped') {
                            throw "EventLog service on ${dc} did not stop within $timeoutSeconds seconds. Final queried state: $currentState. Last sc.exe stop exit code: $scStopExitCode"
                        }
                        Write-Verbose "EventLog service confirmed stopped on ${dc}."
                    } else {
                        Write-Verbose "EventLog service on ${dc} is already stopped or in a state that doesn't require stopping ($currentState)."
                    }

                    # Start the service
                    Write-Verbose "Attempting to start EventLog service on ${dc}..."
                    $process = Start-Process sc.exe -ArgumentList "\\$dc", "start", "EventLog" -Wait -NoNewWindow -PassThru
                    $scStartExitCode = $process.ExitCode
                    
                    # Exit code 0: Success.
                    # Exit code 1056: "An instance of the service is already running."
                    if ($scStartExitCode -ne 0 -and $scStartExitCode -ne 1056) {
                        throw "sc.exe start EventLog on ${dc} failed with exit code $scStartExitCode. Check permissions or sc.exe output manually if needed."
                    }
                    Write-Verbose "sc.exe start command sent to EventLog on ${dc} (ExitCode: $scStartExitCode)."

                    Write-Verbose "Waiting for EventLog service to start on ${dc}..."
                    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                     # Refresh state immediately after sending command before loop
                    $currentState = Get-ServiceStateSC -ComputerName $dc -ServiceName 'EventLog'
                    while ($currentState -ne 'Running' -and $stopWatch.Elapsed.TotalSeconds -lt $timeoutSeconds) {
                        if ($currentState -eq "NotFound" -or $currentState -eq "RpcError" -or $currentState -eq "ErrorInExecution" -or $currentState -eq "QueryError") {
                            throw "Error querying EventLog service state on ${dc} while waiting for start: $currentState. Last sc.exe start exit code: $scStartExitCode"
                        }
                        if ($currentState -eq 'Stopped' -and $stopWatch.Elapsed.TotalSeconds -gt ($timeoutSeconds / 2)) {
                            Write-Warning "EventLog service on $dc still reported as 'Stopped' after $($stopWatch.Elapsed.ToString('hh\:mm\:ss')) of attempting start. Last sc.exe start exit code: $scStartExitCode"
                        }
                        Start-Sleep -Seconds $sleepInterval
                        $currentState = Get-ServiceStateSC -ComputerName $dc -ServiceName 'EventLog'
                        Write-Verbose "Waiting for start... Current state: $currentState (Elapsed: $($stopWatch.Elapsed.ToString('hh\:mm\:ss')))"
                    }
                    $stopWatch.Stop()

                    if ($currentState -ne 'Running') {
                        throw "EventLog service on ${dc} did not start within $timeoutSeconds seconds. Final queried state: $currentState. Last sc.exe start exit code: $scStartExitCode"
                    }
                    Write-Verbose "EventLog service confirmed running on ${dc}."

                    Write-Host "Successfully updated log sizes and restarted EventLog service on ${dc}."
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
