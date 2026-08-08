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
        Write-Host '-OutputPath: Optional working folder where PingCastle is executed before results are moved.'
        Write-Host 'Generated HTML/XML files are moved to $Global:OutputPath\<yyyy-MM-dd> and that folder is opened.'
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

    $destinationRoot = if ([string]::IsNullOrWhiteSpace($Global:OutputPath)) { $workDir } else { $Global:OutputPath }
    $dateFolder = (Get-Date).ToString('yyyy-MM-dd')
    $destinationPath = Join-Path -Path $destinationRoot -ChildPath $dateFolder
    $null = New-Item -Path $destinationPath -ItemType Directory -Force

    $generatedFiles = @(Get-ChildItem -Path $workDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.html', '.xml') })
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
        ExitCode           = $process.ExitCode
    }
}
