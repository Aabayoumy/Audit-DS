function Run-PingCastle {
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$Tag = $Global:PingCastleTag,
        [string]$OutputPath,
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-Server', '-Tag', '-OutputPath'))) {
        Write-Host 'Runs PingCastle in command-line mode (non-interactive healthcheck by default).'
        Write-Host '-Server: Domain to scan. If omitted, current AD domain DNS root is used when available.'
        Write-Host '-Tag: PingCastle release tag used if download is required.'
        Write-Host '-OutputPath: Optional folder where the command is executed and output files are created.'
        return
    }

    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
        if ($MyInvocation.MyCommand.Module -and $MyInvocation.MyCommand.Module.Path) {
            $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Module.Path
        } elseif ($PSScriptRoot) {
            $scriptRoot = Split-Path -Parent $PSScriptRoot
        } else {
            $scriptRoot = (Get-Location).Path
        }
    }

    $pingCastleExe = Get-ChildItem -Path $scriptRoot -Filter 'PingCastle.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pingCastleExe) {
        Write-Host 'PingCastle.exe not found. Running Download-PingCastle first...'
        $downloadInfo = Download-PingCastle -Tag $Tag -ErrorAction Stop
        $pingCastleExePath = $downloadInfo.PingCastleExe
    } else {
        $pingCastleExePath = $pingCastleExe.FullName
    }

    $helpOutput = & $pingCastleExePath --help 2>&1 | Out-String
    $supportsHealthcheck = $helpOutput -match '--healthcheck'
    $supportsServer = $helpOutput -match '--server'

    if (-not ($supportsHealthcheck -and $supportsServer)) {
        throw 'PingCastle command-line help does not include expected --healthcheck/--server options.'
    }

    if ([string]::IsNullOrWhiteSpace($Server)) {
        try {
            $Server = (Get-ADDomain -ErrorAction Stop).DNSRoot
        } catch {
            $Server = $env:USERDNSDOMAIN
        }
    }

    if ([string]::IsNullOrWhiteSpace($Server)) {
        throw 'Unable to determine domain name. Provide -Server explicitly.'
    }

    $workDir = if ([string]::IsNullOrWhiteSpace($OutputPath)) { Split-Path -Parent $pingCastleExePath } else { $OutputPath }
    $null = New-Item -Path $workDir -ItemType Directory -Force

    Write-Host "Recommended silent command: PingCastle.exe --healthcheck --server $Server"

    $arguments = @('--healthcheck', '--server', $Server)
    $process = Start-Process -FilePath $pingCastleExePath -ArgumentList $arguments -WorkingDirectory $workDir -Wait -PassThru

    [PSCustomObject]@{
        PingCastleExe      = $pingCastleExePath
        WorkingDirectory   = $workDir
        Server             = $Server
        RecommendedCommand = "PingCastle.exe --healthcheck --server $Server"
        ExitCode           = $process.ExitCode
    }
}
