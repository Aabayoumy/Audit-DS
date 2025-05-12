function Export-LDAPEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-LDAP here
        [int]$MaxEvents = 10000,
        [int]$Timeout = 180,
        [int]$Days = 7 # Number of days back to limit events
    )
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\LDAP-$($((Get-Date).ToString('ddMMMyy-HHmm')))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $IgnoredDCs =  _GetIgnoredDCs # Load ignored DCs
    $StartTime = (Get-Date).AddDays(-$Days) # Limit to the specified number of days
    foreach ($DC in (Get-ADDomainController -Filter *).HostName | Where-Object { $_ -notin $IgnoredDCs }){
        $OutputFile = "$OutputPath\$($DC).csv"
        Write-Host "[$($DC)] Searching log"
        $job = Start-Job -ScriptBlock {
            param($DC, $StartTime, $MaxEvents)
Get-WinEvent -ComputerName $DC -FilterHashtable @{
    LogName = 'Directory Service';
    ID = 2889;
    StartTime = $StartTime
} -MaxEvents $MaxEvents | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}}, @{Label='SourceIP';Expression={$_.Properties[0].Value}}, @{Label='User';Expression={$_.Properties[1].Value}}
        } -ArgumentList $DC, $StartTime, $MaxEvents

        $job | Wait-Job -Timeout $Timeout | Out-Null

        if ($job.State -eq 'Running') {
            Write-Warning "[$($DC)] Get-WinEvent timed out after $($Timeout) seconds."
            $job | Stop-Job
            $Events = $null
        } elseif ($job.State -eq 'Completed') {
            $Events = $job | Receive-Job
        } else {
             Write-Warning "[$($DC)] Get-WinEvent job failed with state: $($job.State)."
             $Events = $null
        }
        $job | Remove-Job

        if ($Events) {
            $Events | Export-Csv $OutputFile -NoTypeInformation
        } else {
            Write-Warning "[$($DC)] No LDAP events (EventID 2889) found or an error occurred."
        }
    }
}
