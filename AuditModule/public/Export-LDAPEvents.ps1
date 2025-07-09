function Export-LDAPEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-LDAP here
        [int]$MaxEvents = 10000,
        [int]$Timeout = 180,
        [int]$Days = 7, # Number of days back to limit events
        [Parameter(Mandatory = $false)]
        [string[]]$IgnoredDCs = @(), # Array of DC names to ignore
        [switch]$Help,
        [switch]$h
    )

    # Check for help parameters or any other parameters
    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-MaxEvents', '-Timeout', '-Days', '-IgnoredDCs'))) {
        Write-Host "Exports LDAP events from domain controllers."
        Write-Host "-MaxEvents: Maximum number of events to retrieve (default: 10000)."
        Write-Host "-Timeout: Timeout in seconds for Get-WinEvent job (default: 180)."
        Write-Host "-Days: Number of days back from the current date to limit events (default: 7)."
        Write-Host "-IgnoredDCs: Specifies one or more Domain Controller names to ignore (e.g., 'DC1', 'DC2', 'DC3')."
        return
    }

    AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\LDAP-$($((Get-Date).ToString('ddMMMyy-HHmm')))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $StartTime = (Get-Date).AddDays(-$Days) # Limit to the specified number of days
    $SourceIPs = @() # Initialize an array to collect unique SourceIP values
    $allDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $ignoredDCsLower = $IgnoredDCs | ForEach-Object {$_.ToLower()}
    $DCsToProcess = $allDCs | Where-Object { ($_.Split('.')[0]).ToLower() -notin $ignoredDCsLower }
    $totalDCs = $DCsToProcess.Count
    $i = 0
    foreach ($DC in $DCsToProcess){
        $i++
        $OutputFile = "$OutputPath\$($DC).csv"
        Write-Progress -Activity "Exporting LDAP Events" -Status "Processing DC: $($DC)" -CurrentOperation "Processed $i of $totalDCs DCs" -PercentComplete (($i / $totalDCs) * 100)
        Write-Host "[$($DC)] Searching log"
        $job = Start-Job -ScriptBlock {
            param($DC, $StartTime, $MaxEvents)
        Get-WinEvent -ComputerName $DC -FilterHashtable @{
            LogName = 'Directory Service';
            ID = 2889;
            StartTime = $StartTime
        } -MaxEvents $MaxEvents | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}}, @{Label='SourceIP';Expression={$_.Properties[0].Value.Split(':')[0]}}, @{Label='User';Expression={$_.Properties[1].Value}}
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
            $job.Error | ForEach-Object { Write-Error $_ }
            $Events = $null
        }

        if ($Events) {
            $SourceIPs += $Events | Select-Object -ExpandProperty SourceIP | Sort-Object -Unique # Collect unique SourceIP values
            $Events | Select-Object Time, SourceIP, User | Export-Csv $OutputFile -NoTypeInformation
        }
        elseif ($job.State -eq 'Completed') {
            Write-Host "[$($DC)] No LDAP events (EventID 2889) found."
        }
        $job | Remove-Job
    }
    $SourceIPs | Sort-Object -Unique  | Out-File "$OutputPath\SourceIPs.txt" -Encoding UTF8 # Export unique SourceIP values to SourceIPs.txt
        Start-Process "$($OutputPath)"
}
