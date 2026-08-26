function Get-FilteredDCs {
    param([string[]]$IgnoredDCs = @())
    $ignoredLower = $IgnoredDCs | ForEach-Object { $_.ToLower() }
    Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName |
        Where-Object { ($_.Split('.')[0]).ToLower() -notin $ignoredLower }
}

function Invoke-DCEventJob {
    param(
        [Parameter(Mandatory)] [string]$DC,
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [int]$Timeout = 180
    )
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    $job | Wait-Job -Timeout $Timeout | Out-Null
    $state = $job.State
    if ($state -eq 'Running') {
        Write-Warning "[$DC] Get-WinEvent timed out after $Timeout seconds."
        $job | Stop-Job
        $events = $null
    } elseif ($state -eq 'Completed') {
        $events = $job | Receive-Job
    } else {
        Write-Warning "[$DC] Get-WinEvent job failed with state: $state."
        $job.Error | ForEach-Object { Write-Error $_ }
        $events = $null
    }
    $job | Remove-Job
    [PSCustomObject]@{ Events = $events; State = $state }
}
