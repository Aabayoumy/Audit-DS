function Export-NTLMEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-NTLM here
        [int]$MaxEvents = 10000,
        [switch]$AllNTLM,
        [int]$Timeout = 180,
        [int]$Days = 7 # Number of days back to limit events
    )
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\NTLM-$((Get-Date).ToString('ddMMMyy-HHmm'))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $IgnoredDCs =  _GetIgnoredDCs # Load ignored DCs

    # Determine which NTLM versions to filter based on the -AllNTLM switch
    $NtlmFilter = if ($AllNTLM.IsPresent) { @('NTLM V1', 'NTLM V2') } else { @('NTLM V1') }

    foreach ($DC in (Get-ADDomainController -Filter *).HostName | Where-Object { $_ -notin $IgnoredDCs }){
        $OutputFile = "$OutputPath\$($DC).csv"
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
            }
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
             $Events = $null
        }
        $job | Remove-Job

        if ($Events) {
            $Events | Select-Object `
            @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
            @{Label='UserName';Expression={$_.Properties[5].Value}},
            @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
            @{Label='WorkstationIP';Expression={$_.Properties[18].Value}},
            @{Label='LogonType';Expression={$_.properties[8].value}},
            @{Label='LmPackageName';Expression={$_.properties[14].value}},
            @{Label='ImpersonationLevel';Expression={$_.properties[20].value}} | Export-Csv $OutputFile -NoTypeInformation

            # Filter for NTLM V1 events excluding ANONYMOUS LOGON
            $NtlmV1Events = $Events | Where-Object { $_.LmPackageName -eq 'NTLM V1' -and $_.UserName -ne 'ANONYMOUS LOGON' }
            $NtlmV1Count = $NtlmV1Events.Count
            # Update Write-Host to include the count
            Write-Host "[$($DC)] $NtlmV1Count NTLMv1 Events"
        } else {
            Write-Warning "[$($DC)] No NTLM events (EventID 4624) found or an error occurred."
        }
    }
}
