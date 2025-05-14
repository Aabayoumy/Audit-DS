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
- `-Days`: Number of days back from the current date to limit events (default: 7).
- `-IgnoredDCs`: Specifies one or more Domain Controller names to ignore (e.g., 'DC1', 'DC2', 'DC3').

### Export-NTLMEvents
Exports NTLM authentication events from domain controllers.
- `-MaxEvents`: Maximum number of events to retrieve (default: 10000).
- `-AllNTLM`: Includes NTLM V2 events (default: only NTLM V1).
- `-Days`: Number of days back from the current date to limit events (default: 7).
- `-IgnoredDCs`: Specifies one or more Domain Controller names to ignore (e.g., 'DC1', 'DC2', 'DC3').

### Export-ComputersOS
Exports computer OS details and end-of-support status from Active Directory.
- `-OutputPath`: Path to export the CSV file.
- `-ExportAll`: Exports all computers, not just those nearing or past end-of-support.

### Get-DCs
Lists domain controllers with specific details.

### Set-LogSize
Sets the maximum size for Security and Directory Service event logs on domain controllers.
- `-Size`: Specifies the maximum log size in GB (Valid: 2, 3, or 4. Default: 2).
- `-IgnoredDCs`: Specifies one or more Domain Controller names to ignore (e.g., 'DC1', 'DC2', 'DC3').

## Usage
- Download latest release from https://github.com/Aabayoumy/Audit-DS/releases/latest
- Open PowerShell as Admin and CD to extracted folder.
- Set execution policy `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force`
- `Import-Module -Name .\AuditModule -Force`
