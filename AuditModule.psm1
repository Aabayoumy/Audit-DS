# Create global variable OutputPath
$Global:DomainName = (Get-ADDomain).Name
$Global:TodayDate = Get-Date -Format "dd-MMM-yyyy"
$Global:OutputPath = "c:\$DomainName"
# Create the directory if it doesn't exist

# Read ignored DCs from JSON config file
try {
    $IgnoredDCs = Get-Content -Path "$PSScriptRoot\AuditDS.json" -Raw | ConvertFrom-Json
    $Global:IgnoredDCs = $IgnoredDCs
    Write-Host "Ignored DCs loaded from AuditDS.json"
} catch {
    Write-Warning "Could not load ignored DCs from AuditDS.json. $($_.Exception.Message)"
    $Global:IgnoredDCs = @()
}

function Get-NTLMEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-NTLM here
        [int]$MaxEvents = 10000
    )
    $OutputPath = "$Global:OutputPath\NTLM-$($Global:TodayDate)\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    foreach ($DC in (Get-ADDomainController -Filter *).HostName){
        $OutputFile = "$OutputPath\$($DC).csv"
        Write-Host "[$($DC)] Searching log" 
        $Events = Get-WinEvent -ComputerName $DC -Logname security -MaxEvents $MaxEvents  -FilterXPath "Event[System[(EventID=4624)]]and (Event[EventData[Data[@Name='LmPackageName']='NTLM V2']] or Event[EventData[Data[@Name='LmPackageName']='NTLM V1']])" | Select-Object `
        @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
        @{Label='UserName';Expression={$_.Properties[5].Value}},
        @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
        @{Label='WorkstationIP';Expression={$_.Properties[18].Value}},
        @{Label='LogonType';Expression={$_.properties[8].value}},
        @{Label='LmPackageName';Expression={$_.properties[14].value}},
        @{Label='ImpersonationLevel';Expression={$_.properties[20].value}}
        $Events | Export-Csv $OutputFile -NoTypeInformation
        # Filter for NTLM V1 events excluding ANONYMOUS LOGON
        $NtlmV1Events = $Events | Where-Object { $_.LmPackageName -eq 'NTLM V1' -and $_.UserName -ne 'ANONYMOUS LOGON' }
        $NtlmV1Count = $NtlmV1Events.Count
        # Update Write-Host to include the count
        Write-Host "[$($DC)] $NtlmV1Count NTLMv1 Events"
    }
}

function Get-LDAPEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-LDAP here
        [int]$MaxEvents = 10000
    )
    $OutputPath = "$Global:OutputPath\LDAP-$($Global:TodayDate)\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    # Implementation for Audit-LDAP
    Write-Host "Audit-LDAP command executed."
}

# Generate DC list
function Get-Domaininfo {

    $DCs = (Get-ADDomainController -Filter * | Select-Object HostName, IsReadOnly, OperatingSystem, IPv4Address, Site | Sort-Object Site | Format-Table | Out-String).Trim()
    #Print the DCs to the console
    Write-Host "Domain Controllers in $($DomainName):"
    Write-Host $DCs
    # Save the DCs to a file
    $DCsFilePath = Join-Path -Path $Global:OutputPath -ChildPath "DCs.txt"
    $DCs | Out-File -FilePath $DCsFilePath -Encoding UTF8
}



Export-ModuleMember -Function Get-NTLMEvents, Get-LDAPEvents, Get-Domaininfo
