#Requires -Modules ActiveDirectory

function Export-ComputersOS {
    <#
    .SYNOPSIS
    Exports Active Directory computer information including OS details and end-of-support dates to a CSV file.

    .DESCRIPTION
    This function retrieves computer objects from Active Directory, including their OS name,
    OS version (extracting the build number), last logon timestamp, and enabled status.
    It then uses a JSON file (data.json) containing Windows version information to append
    the end-of-extended-support date based on the extracted OS build number.
    
    By default, only computers with "end of support" or "in extended support" status are exported.
    Use the -ExportAll parameter to export all computers regardless of support status.
    
    The final results are exported to a CSV file.

    .NOTES
    Author: Cline
    Date: 2025-05-04
    Version: 1.2 (Added filtering for out-of-support and extended support computers, added -ExportAll switch)
    Requires the Active Directory PowerShell module.
    The data.json file must be in the same directory as this function.

    .EXAMPLE
    Export-ComputersOS
    This will run the function and generate a CSV file containing only computers with "end of support" or "in extended support" status.
    
    .EXAMPLE
    Export-ComputersOS -ExportAll
    This will run the function and generate a CSV file containing all computers, regardless of support status.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, HelpMessage="Path to export the CSV file.")]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false, HelpMessage="Export all computers regardless of support status.")]
        [switch]$ExportAll
    )

    if (-not $OutputPath) {$OutputPath = "$Global:OutputPath"}
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $OutputFile = "$OutputPath\Computers_OS_Support$($((Get-Date).ToString('ddMMMyy-HHmm'))).csv"

    # --- Configuration ---
    $jsonPath = Join-Path $PSScriptRoot "data.json"
    $adProperties = @(
        "Name",
        "OperatingSystem",
        "OperatingSystemVersion", 
        "Enabled",
        "lastLogonTimestamp" # Note: This is replicated from the DC, not live from the computer
    )

    # --- Function Body ---

    # Check if Active Directory module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Active Directory PowerShell module is not installed or available. Please install the RSAT tools."
        return
    }

    # Load OS End-of-Support data from JSON
    Write-Host "Loading OS End-of-Support data from '$jsonPath'..."
    if (-not (Test-Path $jsonPath)) {
        Write-Error "JSON file not found at '$jsonPath'. Please ensure the file exists."
        return
    }
    try {
        $osDataContent = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        # Create a lookup hashtable: Build Number -> { Mainstream = [datetime], Extended = [datetime] }
        $osSupportLookup = @{}
        $osDataContent.windows_versions | ForEach-Object {
            if ($_.build_number -and -not $osSupportLookup.ContainsKey($_.build_number)) {
                # Attempt to parse dates, store $null if parsing fails or date is invalid/missing
                $mainstreamDate = try { [datetime]$_.end_of_mainstream_support } catch { $null }
                $extendedDate = try { [datetime]$_.end_of_extended_support } catch { $null }

                $supportInfo = @{
                    Mainstream = $mainstreamDate
                    Extended   = $extendedDate
                }
                $osSupportLookup.Add($_.build_number, $supportInfo)
            }
        }
        Write-Host "Successfully loaded and processed OS data for $($osSupportLookup.Count) unique build numbers."
    }
    catch {
        Write-Error "Failed to load or parse JSON file '$jsonPath'. Error: $($_.Exception.Message)"
        return
    }


    # Get Active Directory Computers
    Write-Host "Retrieving computers from Active Directory..."
    try {
        # Get all computers (enabled and disabled)
        $adComputers = Get-ADComputer -Filter * -Properties $adProperties -ErrorAction Stop
        Write-Host "Found $($adComputers.Count) computer objects in AD."
    }
    catch {
        Write-Error "Failed to retrieve computers from Active Directory. Error: $($_.Exception.Message)"
        return
    }

    # Process computers and add EOS data
    Write-Host "Processing computer data and adding End-of-Support information..."
    $results = @()
    foreach ($computer in $adComputers) {
        # Convert lastLogonTimestamp (FileTime) to DateTime
        $lastLogonDate = if ($computer.lastLogonTimestamp -and $computer.lastLogonTimestamp -ne 0 -and $computer.lastLogonTimestamp -ne -1) {
            try {
                [DateTime]::FromFileTime($computer.lastLogonTimestamp)
            } catch {
                Write-Warning "Could not convert lastLogonTimestamp '$($computer.lastLogonTimestamp)' for computer '$($computer.Name)'."
                $null
            }
        } else {
            $null # Or set to a specific value like 'Never' or $null
        }

        # Extract Build Number from OperatingSystemVersion (e.g., "10.0 (19045)")
        $buildNumber = $null
        if ($computer.OperatingSystemVersion -match '\((?<build>\d+)\)') {
            $buildNumber = $Matches.build
        } else {
            Write-Warning "Could not extract build number from OperatingSystemVersion '$($computer.OperatingSystemVersion)' for computer '$($computer.Name)'."
        }

        # Look up EOS date using the extracted build number
        $eosDate = $null
        if ($buildNumber -and $osSupportLookup.ContainsKey($buildNumber)) {
            $eosDate = $osSupportLookup[$buildNumber]
        } elseif ($buildNumber) {
            Write-Warning "No EOS date found for extracted build number '$buildNumber' on computer '$($computer.Name)' (OS Version: $($computer.OperatingSystemVersion))."
        } # No warning if build number couldn't be extracted, already warned above

        # Determine Support Status
        $status = "Unknown"
        $currentDate = Get-Date
        if ($buildNumber -and $osSupportLookup.ContainsKey($buildNumber)) {
            $supportInfo = $osSupportLookup[$buildNumber]
            $mainstreamDate = $supportInfo.Mainstream
            $extendedDate = $supportInfo.Extended
            # Determine support status based on current date and EOS dates            
            if ($extendedDate -ne $null) {
                if ($currentDate -gt $extendedDate) {
                    $status = "Out of support"
                } 
                ElseIf ($currentDate -gt $mainstreamDate ) {
                    $status = "in extended support"
                } else {
                    $status = "in support"
                }
                ElseIf ($currentDate -gt $mainstreamDate) {
                $status = "Out of support"
            } else {
                $status = "in support"
            }

            } # If extendedDate is null, status remains "Unknown"
        }
        # Create custom object for output
        $outputObject = [PSCustomObject]@{
            Name                     = $computer.Name
            OperatingSystem          = $computer.OperatingSystem
            BuildNumber              = $buildNumber
            Enabled                  = $computer.Enabled
            LastLogonTimestamp       = $lastLogonDate
            EndOfMainstreamSupport   = if ($supportInfo) { $supportInfo.Mainstream } else { $null }
            EndOfExtendedSupport     = if ($supportInfo) { $supportInfo.Extended } else { $null }
            Status                   = $status
        }
        $results += $outputObject
    }

    # Filter results based on support status if -ExportAll is not specified
    if (-not $ExportAll) {
        $filteredResults = $results | Where-Object { $_.Status -eq "end of support" -or $_.Status -eq "in extended support" }
        Write-Host "Filtered to $($filteredResults.Count) computers with 'end of support' or 'in extended support' status."
        $exportResults = $filteredResults
    } else {
        Write-Host "Exporting all $($results.Count) computers as requested with -ExportAll parameter."
        $exportResults = $results
    }

    # Export results to CSV
    Write-Host "Exporting results to '$OutputFile'..."
    try {
        $exportResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Successfully exported report to '$OutputFile'."
    }
    catch {
        Write-Error "Failed to export results to CSV. Error: $($_.Exception.Message)"
    }

    Write-Host "Function completed."
}
