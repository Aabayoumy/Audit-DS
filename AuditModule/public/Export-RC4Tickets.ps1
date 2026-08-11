function Export-RC4Tickets {
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
        Write-Host 'Exports Kerberos service-ticket events (4769) encrypted with RC4 (0x17) from all domain controllers.'
        Write-Host '-MaxEvents: Maximum number of events to retrieve from each DC (default: 10000).'
        Write-Host '-Timeout: Timeout in seconds for each Get-WinEvent job (default: 180).'
        Write-Host '-Days: Number of days back from current date to query (default: 7).'
        Write-Host '-IgnoredDCs: Specifies one or more Domain Controller names to ignore (e.g., ''DC1'', ''DC2'').'
        return
    }

    if ($Days -lt 1) {
        throw 'Days must be 1 or greater.'
    }

    AssertAdminPrivileges

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error 'Active Directory module is not installed. Please install the RSAT tools.'
        return
    }

    $OutputPath = "$Global:OutputPath\RC4-$((Get-Date).ToString('ddMMMyy-HHmm'))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force

    $start = (Get-Date).AddDays(-$Days)
    $events = @()

    Write-Host 'Enumerating domain controllers...'
    $allDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $ignoredDCsLower = $IgnoredDCs | ForEach-Object { $_.ToLower() }
    $dcs = $allDCs | Where-Object { ($_.Split('.')[0]).ToLower() -notin $ignoredDCsLower }
    $totalDCs = $dcs.Count
    $i = 0

    foreach ($dc in $dcs) {
        $i++
        $outputFile = "$OutputPath\$dc.csv"
        Write-Progress -Activity 'Exporting RC4 Kerberos Tickets' -Status "Processing DC: $dc" -CurrentOperation "Processed $i of $totalDCs DCs" -PercentComplete (($i / $totalDCs) * 100)
        Write-Host "[$dc] Searching log"

        $job = Start-Job -ScriptBlock {
            param($DC, $StartTime, $MaxEvents)
            Get-WinEvent -ComputerName $DC -FilterHashtable @{
                LogName   = 'Security'
                ID        = 4769
                StartTime = $StartTime
            } -MaxEvents $MaxEvents | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $data = @{}
                foreach ($node in $xml.Event.EventData.Data) {
                    $data[$node.Name] = $node.'#text'
                }

                if ($data['TicketEncryptionType'] -eq '0x17') {
                    [PSCustomObject]@{
                        Time                 = $_.TimeCreated.ToString('g')
                        TargetUserName       = $data['TargetUserName']
                        ServiceName          = $data['ServiceName']
                        TicketEncryptionType = $data['TicketEncryptionType']
                        DomainController     = $DC
                    }
                }
            }
        } -ArgumentList $dc, $start, $MaxEvents

        $job | Wait-Job -Timeout $Timeout | Out-Null

        if ($job.State -eq 'Running') {
            Write-Warning "[$dc] Get-WinEvent timed out after $Timeout seconds."
            $job | Stop-Job
            $dcEvents = $null
        } elseif ($job.State -eq 'Completed') {
            $dcEvents = $job | Receive-Job
        } else {
            Write-Warning "[$dc] Get-WinEvent job failed with state: $($job.State)."
            $job.Error | ForEach-Object { Write-Error $_ }
            $dcEvents = $null
        }

        if ($dcEvents) {
            Write-Host "[$dc] $($dcEvents.Count) RC4 ticket events"
            $dcEvents | Export-Csv -NoTypeInformation -Path $outputFile -Encoding UTF8
            $events += $dcEvents
        } elseif ($job.State -eq 'Completed') {
            Write-Host "[$dc] No RC4-encrypted service-ticket events found."
        }

        $job | Remove-Job
    }

    $combinedFile = "$OutputPath\RC4-4769-AllDCs.csv"
    if ($events) {
        $events | Sort-Object Time | Export-Csv -NoTypeInformation -Path $combinedFile -Encoding UTF8
        Write-Host "Saved $($events.Count) RC4 service-ticket events to: $combinedFile"
    } else {
        Write-Host 'No RC4-encrypted Kerberos service-ticket events found in any queried DC.'
    }

    Start-Process "$OutputPath"

    [PSCustomObject]@{
        OutputPath  = $OutputPath
        CombinedCsv = $combinedFile
        EventsCount = $events.Count
        Days        = $Days
        StartTime   = $start
    }
}
