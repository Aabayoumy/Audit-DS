function Export-LDAPEvents {
    [CmdletBinding()]
    param (
        [int]$MaxEvents = 10000,
        [int]$Timeout = 180,
        [int]$Days = 7,
        [Parameter(Mandatory = $false)]
        [string[]]$IgnoredDCs = @(),
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-MaxEvents', '-Timeout', '-Days', '-IgnoredDCs'))) {
        Write-Host "Exports LDAP events from domain controllers."
        Write-Host "-MaxEvents: Maximum number of events to retrieve (default: 10000)."
        Write-Host "-Timeout: Timeout in seconds for Get-WinEvent job (default: 180)."
        Write-Host "-Days: Number of days back from the current date to limit events (default: 7)."
        Write-Host "-IgnoredDCs: Specifies one or more Domain Controller names to ignore (e.g., 'DC1', 'DC2', 'DC3')."
        return
    }

    AssertAdminPrivileges
    $todayFolder = (Get-Date).ToString('yyyy-MM-dd')
    $OutputPath = Join-Path -Path (Join-Path -Path $Global:OutputPath -ChildPath $todayFolder) -ChildPath 'LDAPEvents'
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $StartTime = (Get-Date).AddDays(-$Days)
    $SourceIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $DCsToProcess = Get-FilteredDCs -IgnoredDCs $IgnoredDCs
    $totalDCs = $DCsToProcess.Count
    $i = 0

    foreach ($DC in $DCsToProcess) {
        $i++
        Write-Progress -Activity "Exporting LDAP Events" -Status "Processing DC: $($DC)" -CurrentOperation "Processed $i of $totalDCs DCs" -PercentComplete (($i / $totalDCs) * 100)
        Write-Host "[$($DC)] Searching log"

        $result = Invoke-DCEventJob -DC $DC -Timeout $Timeout -ArgumentList @($DC, $StartTime, $MaxEvents) -ScriptBlock {
            param($DC, $StartTime, $MaxEvents)
            Get-WinEvent -ComputerName $DC -FilterHashtable @{
                LogName = 'Directory Service';
                ID = 2889;
                StartTime = $StartTime
            } -MaxEvents $MaxEvents | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
            @{Label='SourceIP';Expression={$_.Properties[0].Value.Split(':')[0]}},
            @{Label='User';Expression={$_.Properties[1].Value}}
        }

        if ($result.Events) {
            $result.Events | Select-Object -ExpandProperty SourceIP | ForEach-Object { $null = $SourceIPs.Add($_) }
            $result.Events | Select-Object Time, SourceIP, User | Export-Csv "$OutputPath\$($DC).csv" -NoTypeInformation
        } elseif ($result.State -eq 'Completed') {
            Write-Host "[$($DC)] No LDAP events (EventID 2889) found."
        }
    }
    $SourceIPs | Sort-Object | Out-File "$OutputPath\SourceIPs.txt" -Encoding UTF8
    Start-Process "$($OutputPath)"
}
