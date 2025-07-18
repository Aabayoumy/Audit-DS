function Export-NTLMEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-NTLM here
        [int]$MaxEvents = 10000,
        [switch]$AllNTLM,
        [int]$Timeout = 180,
        [int]$Days = 7, # Number of days back to limit events
        [Parameter(Mandatory = $false)]
        [string[]]$IgnoredDCs = @(), # Array of DC names to ignore
        [switch]$Help,
        [switch]$h
    )

    # Check for help parameters or any other parameters
    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-MaxEvents', '-AllNTLM', '-Timeout', '-Days', '-IgnoredDCs'))) {
        Write-Host "Exports NTLM authentication events from domain controllers."
        Write-Host "-MaxEvents: Maximum number of events to retrieve (default: 10000)."
        Write-Host "-AllNTLM: Includes NTLM V2 events (default: only NTLM V1)."
        Write-Host "-Timeout: Timeout in seconds for Get-WinEvent job (default: 180)."
        Write-Host "-Days: Number of days back from the current date to limit events (default: 7)."
        Write-Host "-IgnoredDCs: Specifies one or more Domain Controller names to ignore (e.g., 'DC1', 'DC2', 'DC3')."
        return
    }

    AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\NTLM-$((Get-Date).ToString('ddMMMyy-HHmm'))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force

    # Determine which NTLM versions to filter based on the -AllNTLM switch
    $NtlmFilter = if ($AllNTLM.IsPresent) { @('NTLM V1', 'NTLM V2') } else { @('NTLM V1') }

    $allDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $ignoredDCsLower = $IgnoredDCs | ForEach-Object {$_.ToLower()}
    $DCsToProcess = $allDCs | Where-Object { ($_.Split('.')[0]).ToLower() -notin $ignoredDCsLower }
    $totalDCs = $DCsToProcess.Count
    $i = 0
    foreach ($DC in $DCsToProcess){
        $i++
        $OutputFile = "$OutputPath\$($DC).csv"
        Write-Progress -Activity "Exporting NTLM Events" -Status "Processing DC: $($DC)" -CurrentOperation "Processed $i of $totalDCs DCs" -PercentComplete (($i / $totalDCs) * 100)
        Write-Host "[$($DC)] Searching log"
        $StartTime = (Get-Date).AddDays(-$Days) # Limit to the specified number of days

        $job = Start-Job -ScriptBlock {
            param($DC, $StartTime, $MaxEvents, $NtlmFilter)
            Get-WinEvent -ComputerName $DC -FilterHashtable @{
                LogName = 'Security';
                ID = 4624;
                StartTime = $StartTime
            } -MaxEvents $MaxEvents | Where-Object {
                $_.Properties[14].Value -in $NtlmFilter # Use the dynamic filter
            } | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
            @{Label='User';Expression={$_.Properties[5].Value}},
            @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
            @{Label='WorkstationIP';Expression={$_.Properties[18].Value}},
            @{Label='LogonType';Expression={$_.properties[8].value}},
            @{Label='LmPackageName';Expression={$_.properties[14].value}},
            @{Label='ImpersonationLevel';Expression={$_.properties[20].value}}
        } -ArgumentList $DC, $StartTime, $MaxEvents, $NtlmFilter

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
            # Filter for NTLM V1 events excluding ANONYMOUS LOGON
            $NtlmV1Events = $Events | Where-Object { $_.LmPackageName -eq 'NTLM V1' -and $_.UserName -ne 'ANONYMOUS LOGON' }
            $NtlmV1Count = $NtlmV1Events.Count
            # Update Write-Host to include the count
            Write-Host "[$($DC)] $NtlmV1Count NTLMv1 Events"
            $Events | Select-Object Time, WorkstationName, WorkstationIP, User, LmPackageName  | Export-Csv $OutputFile -NoTypeInformation
        }
        elseif ($job.State -eq 'Completed') {
            Write-Host "[$($DC)] No NTLM events (EventID 4624) found."
        }
        $job | Remove-Job
    }
    Start-Process "$($OutputPath)"
}
