# Function to list Domain Controllers with specific details
function Get-DCs {
    [CmdletBinding()]
    param()

    # Retrieve and format DC information
    return (Get-ADDomainController -Filter * | Select-Object HostName, IsReadOnly, OperatingSystem, IPv4Address, Site | Sort-Object HostName | Format-Table | Out-String).Trim()
}
