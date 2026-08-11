function Export-Assesment {
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$Tag = $Global:PingCastleTag,
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-Server', '-Tag'))) {
        Write-Host 'Runs AD and PingCastle assessment exports, collects results in a single folder, and zips them.'
        Write-Host '-Server: Optional domain value passed to Start-PingCastle.'
        Write-Host '-Tag: Optional PingCastle release tag passed to Start-PingCastle.'
        return
    }

    AssertAdminPrivileges

    $todayFolder = (Get-Date).ToString('yyyy-MM-dd')
    $dateRoot = Join-Path -Path $Global:OutputPath -ChildPath $todayFolder
    $assessmentPath = Join-Path -Path $dateRoot -ChildPath 'Assesment'
    $zipPath = "$assessmentPath.zip"

    $null = New-Item -Path $assessmentPath -ItemType Directory -Force

    Write-Host 'Running Export-ADInfo...'
    Export-ADInfo | Out-Null

    Write-Host 'Running Start-PingCastle...'
    Start-PingCastle -Server $Server -Tag $Tag | Out-Null

    $adInfoPath = Join-Path -Path $dateRoot -ChildPath 'ADInfo'
    $pingCastlePath = Join-Path -Path $dateRoot -ChildPath 'PingCastle'

    if (Test-Path -Path $adInfoPath) {
        $adInfoTarget = Join-Path -Path $assessmentPath -ChildPath 'ADInfo'
        if (Test-Path -Path $adInfoTarget) {
            Remove-Item -Path $adInfoTarget -Recurse -Force
        }
        Copy-Item -Path $adInfoPath -Destination $adInfoTarget -Recurse -Force
    } else {
        Write-Warning "ADInfo folder not found at $adInfoPath"
    }

    if (Test-Path -Path $pingCastlePath) {
        $pingCastleTarget = Join-Path -Path $assessmentPath -ChildPath 'PingCastle'
        if (Test-Path -Path $pingCastleTarget) {
            Remove-Item -Path $pingCastleTarget -Recurse -Force
        }
        Copy-Item -Path $pingCastlePath -Destination $pingCastleTarget -Recurse -Force
    } else {
        Write-Warning "PingCastle folder not found at $pingCastlePath"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -Path $zipPath) {
        Remove-Item -Path $zipPath -Force
    }
    [IO.Compression.ZipFile]::CreateFromDirectory($assessmentPath, $zipPath)

    Start-Process $dateRoot

    [PSCustomObject]@{
        AssessmentPath = $assessmentPath
        ZipPath        = $zipPath
        ADInfoPath     = $adInfoPath
        PingCastlePath = $pingCastlePath
    }
}
