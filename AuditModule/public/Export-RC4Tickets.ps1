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

    $todayFolder = (Get-Date).ToString('yyyy-MM-dd')
    $OutputPath = Join-Path -Path (Join-Path -Path $Global:OutputPath -ChildPath $todayFolder) -ChildPath 'RC4Tickets'
    $null = New-Item -Path $OutputPath -ItemType Directory -Force

    $start = (Get-Date).AddDays(-$Days)
    $allEvents = [System.Collections.Generic.List[object]]::new()

    Write-Host 'Enumerating domain controllers...'
    $dcs = Get-FilteredDCs -IgnoredDCs $IgnoredDCs
    $totalDCs = $dcs.Count
    $i = 0

    foreach ($dc in $dcs) {
        $i++
        Write-Progress -Activity 'Exporting RC4 Kerberos Tickets' -Status "Processing DC: $dc" -CurrentOperation "Processed $i of $totalDCs DCs" -PercentComplete (($i / $totalDCs) * 100)
        Write-Host "[$dc] Searching log"

        $result = Invoke-DCEventJob -DC $dc -Timeout $Timeout -ArgumentList @($dc, $start, $MaxEvents) -ScriptBlock {
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
        }

        if ($result.Events) {
            Write-Host "[$dc] $($result.Events.Count) RC4 ticket events"
            $result.Events | Export-Csv -NoTypeInformation -Path "$OutputPath\$dc.csv" -Encoding UTF8
            foreach ($e in $result.Events) { $allEvents.Add($e) }
        } elseif ($result.State -eq 'Completed') {
            Write-Host "[$dc] No RC4-encrypted service-ticket events found."
        }
    }

    $combinedFile = "$OutputPath\RC4-4769-AllDCs.csv"
    if ($allEvents.Count -gt 0) {
        $allEvents | Sort-Object Time | Export-Csv -NoTypeInformation -Path $combinedFile -Encoding UTF8
        Write-Host "Saved $($allEvents.Count) RC4 service-ticket events to: $combinedFile"
    } else {
        Write-Host 'No RC4-encrypted Kerberos service-ticket events found in any queried DC.'
    }

    Start-Process "$OutputPath"

    [PSCustomObject]@{
        OutputPath  = $OutputPath
        CombinedCsv = $combinedFile
        EventsCount = $allEvents.Count
        Days        = $Days
        StartTime   = $start
    }
}
