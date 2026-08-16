function New-AuditGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name = '_Audit-NTLM-Ldap',

        [Parameter(Mandatory = $false)]
        [string]$Domain,

        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-Name', '-Domain'))) {
        Write-Host 'Creates a new (unlinked) GPO by restoring the bundled _Audit-NTLM-Ldap GPO backup.'
        Write-Host 'The GPO enables NTLM auditing (Security Options), sets the Security log to 2 GB, and enables LDAP diagnostics auditing (Registry preference).'
        Write-Host '-Name: GPO display name (default: _Audit-NTLM-Ldap).'
        Write-Host '-Domain: Target domain FQDN. If omitted, the current AD domain is used.'
        return
    }

    # Ensure the GroupPolicy module is available
    if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
        Write-Error "GroupPolicy module is required but not found. Install RSAT Group Policy Management features first."
        return
    }
    Import-Module GroupPolicy -ErrorAction Stop

    # Ensure the ActiveDirectory module is available
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        Write-Error "ActiveDirectory module is required but not found."
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $domainFqdn = $Domain
    if (-not $domainFqdn) {
        $domainFqdn = (Get-ADDomain).DNSRoot
    }

    # Create only a NEW GPO - never overwrite an existing one
    if (Get-GPO -Name $Name -Domain $domainFqdn -ErrorAction SilentlyContinue) {
        Write-Error "A GPO named '$Name' already exists in $domainFqdn. Delete it or use a different -Name."
        return
    }

    # Locate the bundled GPO backup shipped with the module
    $backupRoot = Join-Path -Path $PSScriptRoot -ChildPath 'GPO'
    if (-not (Test-Path $backupRoot)) {
        Write-Error "GPO backup folder not found at '$backupRoot'. The module may be missing files."
        return
    }
    $backupFolder = Get-ChildItem -Path $backupRoot -Directory |
        Where-Object { $_.Name -match '^\{[0-9a-fA-F-]{36}\}$' } |
        Select-Object -First 1
    if (-not $backupFolder) {
        Write-Error "No GPO backup folder found under '$backupRoot'. Expected a folder named like '{GUID}'."
        return
    }
    $backupId = $backupFolder.Name

    Write-Verbose "Restoring GPO backup '$backupId' as '$Name' in domain $domainFqdn"
    try {
        $gpo = Import-GPO -BackupId $backupId -TargetName $Name -Path $backupRoot -Domain $domainFqdn -CreateIfNeeded -ErrorAction Stop
    } catch {
        throw "Failed to restore GPO '$Name' from backup: $($_.Exception.Message)"
    }

    Write-Host "Audit GPO '$Name' created from bundled backup (not linked)." -ForegroundColor Green
    Write-Host "The GPO was NOT linked. Don't forget to review and link the GPO." -ForegroundColor Green

    return $gpo
}