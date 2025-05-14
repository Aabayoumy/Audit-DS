# Function to list Domain Controllers with specific details
# Function to list Domain Controllers with specific details
function Get-DCs {
    [CmdletBinding()]
    param(
        [switch]$Help,
        [switch]$h
    )

    # Check for help parameters or any other parameters
    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help'))) {
        Write-Host "Lists domain controllers with specific details."
        return
    }

    # Retrieve DC information
    $DCs = Get-ADDomainController -Filter * | Select-Object HostName, IsReadOnly, OperatingSystem, IPv4Address, Site | Sort-Object HostName

    # Check port 135 reachability for each DC
    $OutputTable = foreach ($dc in $DCs) {
        [PSCustomObject]@{
            HostName = $dc.HostName
            IsReadOnly = $dc.IsReadOnly
            OperatingSystem = $dc.OperatingSystem
            IPv4Address = $dc.IPv4Address
            Site = $dc.Site
            lastlogontimestamp = $dc.lastlogontimestamp
        }
    }

    # Output the results in a table format
    return $OutputTable | Format-Table | Out-String
}
