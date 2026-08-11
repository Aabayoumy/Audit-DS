function Export-RC4Tickets {
    [CmdletBinding()]
    param(
        [int]$DaysBack = 1,
        [string]$CsvPath,
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-DaysBack', '-CsvPath'))) {
        Write-Host 'Exports Kerberos service-ticket events (4769) encrypted with RC4 (0x17) from all domain controllers.'
        Write-Host '-DaysBack: Number of days of logs to query (default: 1).'
        Write-Host '-CsvPath: Full CSV output path (default: $Global:OutputPath\RC4-4769-<date>.csv).'
        return
    }

    if ($DaysBack -lt 1) {
        throw 'DaysBack must be 1 or greater.'
    }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error 'Active Directory module is not installed. Please install the RSAT tools.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        $basePath = if ([string]::IsNullOrWhiteSpace($Global:OutputPath)) { (Get-Location).Path } else { $Global:OutputPath }
        $null = New-Item -Path $basePath -ItemType Directory -Force
        $CsvPath = Join-Path -Path $basePath -ChildPath ("RC4-4769-{0}.csv" -f (Get-Date).ToString('yyyyMMdd-HHmm'))
    }

    $start = (Get-Date).AddDays(-$DaysBack)
    $events = New-Object System.Collections.Generic.List[object]

    Write-Host 'Enumerating domain controllers...'
    $dcs = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)

    foreach ($dc in $dcs) {
        Write-Host "Querying $dc..."
        try {
            $winEvents = Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName = 'Security'; Id = 4769; StartTime = $start } -ErrorAction Stop
            foreach ($event in $winEvents) {
                $xml = [xml]$event.ToXml()
                $data = @{}
                foreach ($node in $xml.Event.EventData.Data) {
                    $data[$node.Name] = $node.'#text'
                }

                if ($data['TicketEncryptionType'] -eq '0x17') {
                    $events.Add([PSCustomObject]@{
                        DomainController     = $dc
                        TimeCreated          = $event.TimeCreated
                        TargetUserName       = $data['TargetUserName']
                        ServiceName          = $data['ServiceName']
                        TicketEncryptionType = $data['TicketEncryptionType']
                    })
                }
            }
        }
        catch {
            Write-Warning "Failed to query ${dc}: $($_.Exception.Message)"
        }
    }

    if ($events.Count -gt 0) {
        $events | Sort-Object TimeCreated | Export-Csv -NoTypeInformation -Path $CsvPath -Encoding UTF8
        Write-Host "Saved $($events.Count) RC4 service-ticket events to: $CsvPath"
    }
    else {
        Write-Host 'No RC4-encrypted Kerberos service-ticket events found.'
    }

    [PSCustomObject]@{
        CsvPath     = $CsvPath
        EventsCount = $events.Count
        DaysBack    = $DaysBack
        StartTime   = $start
    }
}
