function Start-PingCastle {
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$Tag = $Global:PingCastleTag,
        [string]$OutputPath,
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-Server', '-Tag', '-OutputPath'))) {
        Write-Host 'Runs PingCastle in command-line mode (non-interactive healthcheck + SMB scanner).'
        Write-Host '-Server: Domain to scan. If omitted, current AD domain DNS root is used when available.'
        Write-Host '-Tag: PingCastle release tag used if download is required.'
        Write-Host '-OutputPath: Optional working folder where PingCastle is executed before results are moved.'
        Write-Host 'Runs healthcheck and SMB scanner in all-systems mode silently when supported.'
        Write-Host 'Generated report files are moved to $Global:OutputPath\<yyyy-MM-dd>\PingCastle and that folder is opened.'
        return
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

    $pingCastleExe = Get-ChildItem -Path $scriptRoot -Filter 'PingCastle.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pingCastleExe) {
        Write-Host 'PingCastle.exe not found. Running Install-PingCastle first...'
        $downloadInfo = Install-PingCastle -Tag $Tag -ErrorAction Stop
        $pingCastleExePath = $downloadInfo.PingCastleExe
    } else {
        $pingCastleExePath = $pingCastleExe.FullName
    }

    $helpOutput = & $pingCastleExePath --help 2>&1 | Out-String
    $supportsHealthcheck = $helpOutput -match '--healthcheck'
    $supportsServer = $helpOutput -match '--server'
    $supportsScanner = $helpOutput -match '--scanner'
    $supportsScModeAll = $helpOutput -match '--scmode-all'

    if (-not ($supportsHealthcheck -and $supportsServer)) {
        throw 'PingCastle command-line help does not include expected --healthcheck/--server options.'
    }

    if (-not ($supportsScanner -and $supportsScModeAll)) {
        Write-Warning 'PingCastle help does not show --scanner/--scmode-all. SMB scanner may run in interactive mode or be unavailable in this version.'
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
    Write-Host "Recommended silent SMB scanner command: PingCastle.exe --scanner smb --scmode-all --server $Server"

    $snapshotBefore = @{}
    Get-ChildItem -Path $workDir -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $snapshotBefore[$_.FullName] = $_.LastWriteTimeUtc
    }

    $arguments = @('--healthcheck', '--server', $Server)
    $healthcheckProcess = Start-Process -FilePath $pingCastleExePath -ArgumentList $arguments -WorkingDirectory $workDir -Wait -PassThru

    $scannerExitCode = $null
    if ($supportsScanner -and $supportsScModeAll) {
        $scannerArguments = @('--scanner', 'smb', '--scmode-all', '--server', $Server)
        $scannerProcess = Start-Process -FilePath $pingCastleExePath -ArgumentList $scannerArguments -WorkingDirectory $workDir -Wait -PassThru
        $scannerExitCode = $scannerProcess.ExitCode
    }

    $destinationRoot = if ([string]::IsNullOrWhiteSpace($Global:OutputPath)) { $workDir } else { $Global:OutputPath }
    $dateFolder = (Get-Date).ToString('yyyy-MM-dd')
    $destinationPath = Join-Path -Path (Join-Path -Path $destinationRoot -ChildPath $dateFolder) -ChildPath 'PingCastle'
    $null = New-Item -Path $destinationPath -ItemType Directory -Force

    $generatedFiles = @(Get-ChildItem -Path $workDir -File -Recurse -ErrorAction SilentlyContinue | Where-Object {
        ($_.Extension -in @('.html', '.xml', '.txt', '.csv', '.json')) -and (
            -not $snapshotBefore.ContainsKey($_.FullName) -or
            $_.LastWriteTimeUtc -gt $snapshotBefore[$_.FullName]
        )
    })
    foreach ($file in $generatedFiles) {
        $targetFile = Join-Path -Path $destinationPath -ChildPath $file.Name
        if ($file.FullName -ne $targetFile) {
            Move-Item -Path $file.FullName -Destination $targetFile -Force
        }
    }

    Start-Process $destinationPath | Out-Null

    [PSCustomObject]@{
        PingCastleExe      = $pingCastleExePath
        WorkingDirectory   = $workDir
        ResultPath         = $destinationPath
        MovedFilesCount    = $generatedFiles.Count
        Server             = $Server
        RecommendedCommand = "PingCastle.exe --healthcheck --server $Server"
        RecommendedScannerCommand = "PingCastle.exe --scanner smb --scmode-all --server $Server"
        HealthcheckExitCode = $healthcheckProcess.ExitCode
        ScannerExitCode     = $scannerExitCode
    }
}
