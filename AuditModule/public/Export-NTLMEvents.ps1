function Export-NTLMEvents {
    [CmdletBinding()]
    param (
        [int]$MaxEvents = 10000,
        [switch]$AllNTLM,
        [int]$Timeout = 180,
        [int]$Days = 7,
        [Parameter(Mandatory = $false)]
        [string[]]$IgnoredDCs = @(),
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-MaxEvents', '-AllNTLM', '-Timeout', '-Days', '-IgnoredDCs'))) {
        Write-Host "Exports NTLM authentication events from domain controllers."
        Write-Host "-MaxEvents: Maximum number of events to retrieve (default: 10000)."
        Write-Host "-AllNTLM: Includes NTLM V2 events (default: only NTLM V1)."
        Write-Host "-Timeout: Timeout in seconds for Get-WinEvent job (default: 180)."
        Write-Host "-Days: Number of days back from the current date to limit events (default: 7)."
        Write-Host "-IgnoredDCs: Specifies one or more Domain Controller names to ignore (e.g., 'DC1', 'DC2', 'DC3')."
        return
    }

    AssertAdminPrivileges
    $todayFolder = (Get-Date).ToString('yyyy-MM-dd')
    $OutputPath = Join-Path -Path (Join-Path -Path $Global:OutputPath -ChildPath $todayFolder) -ChildPath 'NTLMEvents'
    $null = New-Item -Path $OutputPath -ItemType Directory -Force

    $NtlmFilter = if ($AllNTLM.IsPresent) { @('NTLM V1', 'NTLM V2') } else { @('NTLM V1') }
    $StartTime = (Get-Date).AddDays(-$Days)
    $DCsToProcess = Get-FilteredDCs -IgnoredDCs $IgnoredDCs
    $totalDCs = $DCsToProcess.Count
    $i = 0

    foreach ($DC in $DCsToProcess) {
        $i++
        Write-Progress -Activity "Exporting NTLM Events" -Status "Processing DC: $($DC)" -CurrentOperation "Processed $i of $totalDCs DCs" -PercentComplete (($i / $totalDCs) * 100)
        Write-Host "[$($DC)] Searching log"

        $result = Invoke-DCEventJob -DC $DC -Timeout $Timeout -ArgumentList @($DC, $StartTime, $MaxEvents, $NtlmFilter) -ScriptBlock {
            param($DC, $StartTime, $MaxEvents, $NtlmFilter)
            Get-WinEvent -ComputerName $DC -FilterHashtable @{
                LogName = 'Security';
                ID = 4624;
                StartTime = $StartTime
            } -MaxEvents $MaxEvents | Where-Object {
                $_.Properties[14].Value -in $NtlmFilter
            } | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
            @{Label='User';Expression={$_.Properties[5].Value}},
            @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
            @{Label='WorkstationIP';Expression={$_.Properties[18].Value}},
            @{Label='LogonType';Expression={$_.properties[8].value}},
            @{Label='LmPackageName';Expression={$_.properties[14].value}},
            @{Label='ImpersonationLevel';Expression={$_.properties[20].value}}
        }

        if ($result.Events) {
            $NtlmV1Events = $result.Events | Where-Object { $_.LmPackageName -eq 'NTLM V1' -and $_.User -ne 'ANONYMOUS LOGON' }
            Write-Host "[$($DC)] $($NtlmV1Events.Count) NTLMv1 Events"
            $NtlmV1Events | Select-Object Time, WorkstationName, WorkstationIP, User, LmPackageName | Export-Csv "$OutputPath\$($DC).csv" -NoTypeInformation
        } elseif ($result.State -eq 'Completed') {
            Write-Host "[$($DC)] No NTLM events (EventID 4624) found."
        }
    }
    Start-Process "$($OutputPath)"
}
