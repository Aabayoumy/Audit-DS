function Export-LDAPEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-LDAP here
        [int]$MaxEvents = 10000
    )
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\LDAP-$($((Get-Date).ToString('ddMMMyy-HHmm')))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $IgnoredDCs =  _GetIgnoredDCs # Load ignored DCs
    $StartTime = (Get-Date).AddDays(-7) # Limit to the last 7 days
    foreach ($DC in (Get-ADDomainController -Filter *).HostName | Where-Object { $_ -notin $IgnoredDCs }){
        $OutputFile = "$OutputPath\$($DC).csv"
        Write-Host "[$($DC)] Searching log"
        $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
            LogName = 'Directory Service';
            ID = 2889;
            StartTime = $StartTime
        } -MaxEvents $MaxEvents | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},   @{Label='SourceIP';Expression={($_.Properties[0].Value -split ':')[0]}},    @{Label='User';Expression={$_.Properties[1].Value}}
        if ($Events) {
            $Events | Export-Csv $OutputFile -NoTypeInformation
        } else {
            Write-Host "No LDAP events (EventID 2889) found on $DC."
        }
    }
}
