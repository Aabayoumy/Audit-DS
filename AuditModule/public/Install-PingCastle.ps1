function Install-PingCastle {
    [CmdletBinding()]
    param(
        [string]$Tag = $Global:PingCastleTag,
        [switch]$Force,
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-Tag', '-Force'))) {
        Write-Host 'Downloads and extracts a specific PingCastle release in the module folder.'
        Write-Host '-Tag: PingCastle release tag (default from settings: $Global:PingCastleTag).'
        Write-Host '-Force: Re-download and re-extract even if PingCastle.exe already exists.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        throw 'PingCastle tag is empty. Set $Global:PingCastleTag or use -Tag.'
    }

    $scriptRoot = $null
    if ($MyInvocation.MyCommand.Path) {
        $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    } elseif ($PSScriptRoot) {
        $scriptRoot = Split-Path -Parent $PSScriptRoot
    } elseif ($MyInvocation.MyCommand.Module -and $MyInvocation.MyCommand.Module.Path) {
        $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Module.Path
    }
    if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
        $scriptRoot = (Get-Location).Path
    }

    $existingExe = Get-ChildItem -Path $scriptRoot -Filter 'PingCastle.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existingExe -and -not $Force.IsPresent) {
        Write-Host "PingCastle already exists at: $($existingExe.FullName)"
        return [PSCustomObject]@{
            Version          = $Tag
            Downloaded       = $false
            Extracted        = $false
            PingCastleExe    = $existingExe.FullName
            WorkingDirectory = $existingExe.DirectoryName
        }
    }

    $zipFileName = "PingCastle_$Tag.zip"
    $downloadUrl = "https://github.com/netwrix/pingcastle/releases/download/$Tag/$zipFileName"
    $zipPath = Join-Path -Path $scriptRoot -ChildPath $zipFileName
    $extractPath = Join-Path -Path $scriptRoot -ChildPath "PingCastle-$Tag"
    $iwrParams = @{ Uri = $downloadUrl; OutFile = $zipPath; ErrorAction = 'Stop' }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $iwrParams.UseBasicParsing = $true
    }

    Write-Host "Downloading PingCastle $Tag from: $downloadUrl"
    Invoke-WebRequest @iwrParams

    if (Test-Path -Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force
    }

    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

    $pingCastleExe = Get-ChildItem -Path $extractPath -Filter 'PingCastle.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pingCastleExe) {
        throw "PingCastle.exe was not found after extraction in $extractPath"
    }

    [PSCustomObject]@{
        Version          = $Tag
        Downloaded       = $true
        Extracted        = $true
        ZipPath          = $zipPath
        ExtractPath      = $extractPath
        PingCastleExe    = $pingCastleExe.FullName
        WorkingDirectory = $pingCastleExe.DirectoryName
    }
}
