# Audit-DS

This repository contains the Audit-DS module.

## Description

This module is designed for DS auditing purposes. More details will be added soon.

## Functions

### Enable-Audit
Imports GPO settings to enable auditing.

### Export-ADInfo
Exports comprehensive Active Directory information to files.
- `-zip`: Compresses output files into a zip archive.

### Export-AdminUsers
Exports administrative users based on group membership and adminCount.
- `-OutputPath`: Path to export the CSV file.

### Export-LDAPEvents
Exports LDAP events from domain controllers.
- `-MaxEvents`: Maximum number of events to retrieve (default: 10000).

### Export-NTLMEvents
Exports NTLM authentication events from domain controllers.
- `-MaxEvents`: Maximum number of events to retrieve (default: 10000).
- `-AllNTLM`: Includes NTLM V2 events (default: only NTLM V1).

### Get-DCs
Lists domain controllers with specific details.

## Usage
Copy this script and run it on Powershell As admin 
    ```powershell
   $ErrorActionPreference = 'Stop'
$repoUrl = "https://github.com/Aabayoumy/Audit-DS/archive/refs/heads/main.zip"
$zipFile = "Audit-DS-main.zip" 
$extractPath = "." 
$moduleFolderName = "Audit-DS-main" 
$modulePath = Join-Path -Path $extractPath -ChildPath (Join-Path -Path $moduleFolderName -ChildPath "AuditModule")
$targetExtractDir = Join-Path -Path $extractPath -ChildPath $moduleFolderName

try {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
    if ($currentPolicy -ne 'RemoteSigned' -and $currentPolicy -ne 'Unrestricted' -and $currentPolicy -ne 'Bypass') {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    }
} catch { Write-Warning "Failed to set Execution Policy: $($_.Exception.Message). Manual check might be needed." }

try {
    if (Test-Path $zipFile) { Remove-Item -Path $zipFile -Force -ErrorAction SilentlyContinue }
    Invoke-WebRequest -Uri $repoUrl -OutFile $zipFile -UseBasicParsing
} catch { Write-Error "FATAL: Failed to download module: $($_.Exception.Message)"; exit 1 }

try {
    if (Test-Path $targetExtractDir) { Remove-Item -Path $targetExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
    Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force
    if (-not (Test-Path $modulePath)) { throw "Module path '$modulePath' not found after extraction." }
} catch { Write-Error "FATAL: Failed to extract module: $($_.Exception.Message)"; Remove-Item -Path $zipFile -Force -ErrorAction SilentlyContinue; exit 1 }

try {
    Import-Module -Name $modulePath -Force
    Write-Host "AuditModule imported successfully. Use Get-Command -Module AuditModule to see available commands."
} catch { Write-Error "FATAL: Failed to import AuditModule: $($_.Exception.Message)"; Remove-Item -Path $zipFile -Force -ErrorAction SilentlyContinue; Remove-Item -Path $targetExtractDir -Recurse -Force -ErrorAction SilentlyContinue; exit 1 }

try {
    Remove-Item -Path $zipFile -Force
} catch { Write-Warning "Failed to remove zip file '$zipFile': $($_.Exception.Message). Manual removal may be needed." }

Write-Host "Audit-DS Setup Complete."

    
    ```
