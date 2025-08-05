function Export-SMB1Events {
    [CmdletBinding()]
    param (
        [int]$MaxEvents = 10000,
        [int]$Days = 7,
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-MaxEvents', '-Days'))) {
        Write-Host "Exports SMB1 access events from the local server."
        Write-Host "-MaxEvents: Maximum number of events to retrieve (default: 10000)."
        Write-Host "-Days: Number of days back from the current date to limit events (default: 7)."
        return
    }

    AssertAdminPrivileges # Check for admin privileges

    Write-Host "Checking SMB1 status and audit settings on the local server."
    
    $smb1Config = Get-SmbServerConfiguration
    if (-not $smb1Config.EnableSMB1Protocol) {
        Write-Warning "SMB1 protocol is not enabled on this server. Exiting."
        return
    }

    if (-not $smb1Config.AuditSmb1Access) {
        Write-Warning "SMB1 auditing is not enabled. Enabling it now."
        try {
            Set-SmbServerConfiguration -AuditSmb1Access $true -Force -ErrorAction Stop
            Write-Warning "SMB1 auditing has been enabled. Please run the script again to collect logs after some activity has occurred. Exiting for now."
        } catch {
            Write-Error "Failed to enable SMB1 auditing. Error: $_"
        }
        return
    }

    Write-Host "SMB1 is enabled and auditing is active. Exporting events."

    $OutputPath = "$Global:OutputPath\SMB1-$($((Get-Date).ToString('ddMMMyy-HHmm')))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $OutputFile = "$OutputPath\SMB1_Events.csv"
    $StartTime = (Get-Date).AddDays(-$Days)

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-SMBServer/Audit';
            ID = 3000;
            StartTime = $StartTime
        } -MaxEvents $MaxEvents -ErrorAction Stop | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}}, @{Label='ClientAddress';Expression={$_.Properties[0].Value}}, @{Label='UserName';Expression={$_.Properties[1].Value}}, @{Label='SessionID';Expression={$_.Properties[2].Value}}

        if ($Events) {
            $uniqueIPs = $Events.ClientAddress | Sort-Object -Unique
            Write-Host "Unique client IP addresses found: $($uniqueIPs -join ', ')"
            $ipOutputFile = "$OutputPath\SMB1_Source_IPs.txt"
            $uniqueIPs | Out-File -FilePath $ipOutputFile
            $Events | Export-Csv -Path $OutputFile -NoTypeInformation         
            Write-Host "Successfully exported SMB1 events to $OutputFile and unique IPs to $ipOutputFile"
            Import-Csv -Path $OutputFile | Out-GridView
        } else {
            Write-Host "No SMB1 events (EventID 3000) found within the last $Days days."
            $choice = Read-Host "Do you want to disable SMB1 and SMB1 auditing? (Y = Yes, Enter/Anything = No)"
            if ($choice -eq 'Y' -or $choice -eq 'y') {
                Write-Host "Disabling SMB1 auditing..."
                Set-SmbServerConfiguration -AuditSmb1Access $false -Force  -Confirm:$false
                Write-Host "Disabling SMB1 protocol..."
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force  -Confirm:$false
                Write-Host "SMB1 and SMB1 auditing have been disabled."
            }
        }
    } catch {
        Write-Error "An error occurred while exporting SMB1 events: $_"
    }
}
