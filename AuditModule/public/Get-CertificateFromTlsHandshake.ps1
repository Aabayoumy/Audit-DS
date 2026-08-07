function Get-CertificateFromTlsHandshake {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [Alias('DCName')]
        [string]$HostName,

        [int]$Port = 636,

        [string]$Destination,

        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-HostName', '-DCName', '-Port', '-Destination'))) {
        Write-Host 'Gets the remote certificate presented during a TLS handshake.'
        Write-Host '-HostName/-DCName: Target host. If omitted, the domain PDC emulator is used.'
        Write-Host '-Port: TLS port (default: 636).'
        Write-Host '-Destination: Optional path to save the raw certificate bytes (DER).'
        return
    }

    if ([string]::IsNullOrWhiteSpace($HostName)) {
        $domain = Get-ADDomain -ErrorAction Stop
        $HostName = $domain.PDCEmulator
        Write-Host "HostName not specified. Using PDC emulator: $HostName"
    }

    $tcp = $null
    $ssl = $null
    $state = @{}

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, {
            param($Sender, $Certificate, $Chain, $SslPolicyErrors)
            if ($Certificate) {
                $state.cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Certificate)
            }
            return $true
        })

        $ssl.AuthenticateAsClient($HostName)
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }

    if (-not $state.cert) {
        throw "No certificate was captured from the TLS handshake with ${HostName}:$Port."
    }

    if (-not [string]::IsNullOrWhiteSpace($Destination)) {
        $asByteStream = if ($PSEdition -eq 'Core') { @{ AsByteStream = $true } } else { @{ Encoding = 'Byte' } }
        Set-Content -Path $Destination -Value $state.cert.GetRawCertData() @asByteStream
    }

    return $state.cert
}
