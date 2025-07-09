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
        [switch]$ExportAll,
        [switch]$Help,
        [switch]$h
    )

    # Check for help parameters or any other parameters
    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-OutputPath', '-ExportAll'))) {
        Write-Host "Exports computer OS details and end-of-support status from Active Directory."
        Write-Host "-OutputPath: Path to export the CSV file."
        Write-Host "-ExportAll: Exports all computers, not just those nearing or past end-of-support."
        return
    }

    if (-not $OutputPath) {$OutputPath = "$Global:OutputPath"}
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $OutputFile = "$OutputPath\Computers_OS_Support$($((Get-Date).ToString('ddMMMyy-HHmm'))).csv"

    # --- Configuration ---
    $jsonData = @'
{
    "windows_versions": [
      {
        "version": "Windows XP",
        "build_number": "2600",
        "end_of_mainstream_support": "2009-04-14"
      },
      {
        "version": "Windows Vista",
        "build_number": "6000",
        "end_of_mainstream_support": "2012-04-10"
      },
      {
        "version": "Windows 7",
        "build_number": "7600",
        "end_of_mainstream_support": "2015-01-13",
        "note": "Extended Security Updates (ESU) available until 2023-01-10 for paying customers"
      },
      {
        "version": "Windows 8",
        "build_number": "9200",
        "end_of_mainstream_support": "2016-01-12",
        "note": "Users required to upgrade to Windows 8.1 for continued support"
      },
      {
        "version": "Windows 8.1",
        "build_number": "9600",
        "end_of_mainstream_support": "2018-01-09"
      },
      {
        "version": "Windows 10 (All Editions, 22H2)",
        "build_number": "19045",
        "end_of_mainstream_support": "2025-10-14",
        "note": "Final version 22H2; ESU available for consumers ($30/year) until 2026-10-14, businesses up to 2028-10-14"
      },
      {
        "version": "Windows 10 Enterprise LTSC 2015",
        "build_number": "10240",
        "end_of_mainstream_support": "2020-10-13"
      },
      {
        "version": "Windows 10 Enterprise LTSC 2016",
        "build_number": "14393",
        "end_of_mainstream_support": "2021-10-12"
      },
      {
        "version": "Windows 10 Enterprise LTSC 2019",
        "build_number": "17763",
        "end_of_mainstream_support": "2024-01-09"
      },
      {
        "version": "Windows 10 Enterprise LTSC 2021",
        "build_number": "19044",
        "end_of_mainstream_support": "2027-01-12"
      },
      {
        "version": "Windows 11 (21H2)",
        "build_number": "22000",
        "end_of_mainstream_support": "2023-10-10",
        "note": "Enterprise and Education editions only for extended support"
      },
      {
        "version": "Windows 11 (22H2)",
        "build_number": "22621",
        "end_of_mainstream_support": "2024-10-14",
        "note": "Enterprise and Education editions"
      },
      {
        "version": "Windows 11 (23H2)",
        "build_number": "22631",
        "end_of_mainstream_support": "2025-11-11",
        "note": "Projected dates based on 24-month support cycle for Enterprise/Education"
      },
      {
        "version": "Windows 11 (24H2)",
        "build_number": "26100",
        "end_of_mainstream_support": "2026-10-13",
        "note": "Projected dates based on 24-month support cycle for Enterprise/Education"
      },
      {
        "version": "Windows 11 IoT Enterprise LTSC 2021",
        "build_number": "19044",
        "end_of_mainstream_support": "2027-01-12"
      },
      {
        "version": "Windows Server 2003",
        "build_number": "3790",
        "end_of_mainstream_support": "2010-07-13",
        "end_of_extended_support": "2015-07-14"
      },
      {
        "version": "Windows Server 2008",
        "build_number": "6001",
        "end_of_mainstream_support": "2015-01-13",
        "end_of_extended_support": "2020-01-14",
        "note": "ESU available until 2023-01-10, or 2024-01-09 on Azure"
      },
      {
        "version": "Windows Server 2008 R2",
        "build_number": "7600",
        "end_of_mainstream_support": "2015-01-13",
        "end_of_extended_support": "2020-01-14",
        "note": "ESU available until 2023-01-10, or 2024-01-09 on Azure"
      },
      {
        "version": "Windows Server 2012",
        "build_number": "9200",
        "end_of_mainstream_support": "2018-10-09",
        "end_of_extended_support": "2023-10-10",
        "note": "ESU available until 2026-10-13"
      },
      {
        "version": "Windows Server 2012 R2",
        "build_number": "9600",
        "end_of_mainstream_support": "2018-10-09",
        "end_of_extended_support": "2023-10-10",
        "note": "ESU available until 2026-10-13"
      },
      {
        "version": "Windows Server 2016",
        "build_number": "14393",
        "end_of_mainstream_support": "2022-01-11",
        "end_of_extended_support": "2027-01-12"
      },
      {
        "version": "Windows Server 2019",
        "build_number": "17763",
        "end_of_mainstream_support": "2024-01-09",
        "end_of_extended_support": "2029-01-09"
      },
      {
        "version": "Windows Server 2022",
        "build_number": "20348",
        "end_of_mainstream_support": "2026-10-13",
        "end_of_extended_support": "2031-10-14"
      },
      {
        "version": "Windows Server 2025",
        "build_number": "26100",
        "end_of_mainstream_support": "2029-10-09",
        "end_of_extended_support": "2034-10-09",
        "note": "Projected dates based on LTSC 5+5 year lifecycle"
      }
    ]
  }
'@
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
    # Write-Host "Loading OS End-of-Support data from embedded string..."
    try {
        $osDataContent = $jsonData | ConvertFrom-Json
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
        # Write-Host "Successfully loaded and processed OS data for $($osSupportLookup.Count) unique build numbers."
    }
    catch {
        Write-Error "Failed to load or parse embedded JSON data. Error: $($_.Exception.Message)"
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
            }
            ElseIf ($currentDate -gt $mainstreamDate) {
                $status = "Out of support"
            } else {
                $status = "in support"
            } 
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
        $filteredResults = $results | Where-Object { $_.Status -ne "in support" }
        # Write-Host "Filtered to $($filteredResults.Count) computers without 'in support' status."
        $exportResults = $filteredResults
    } else {
        # Write-Host "Exporting all $($results.Count) computers as requested with -ExportAll parameter."
        $exportResults = $results
    }

    # Export results to CSV
    # Write-Host "Exporting results to '$OutputFile'..."
    try {
        $exportResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        # Write-Host "Successfully exported report to '$OutputFile'."
    }
    catch {
        Write-Error "Failed to export results to CSV. Error: $($_.Exception.Message)"
    }

    # Write-Host "Function completed."
}
