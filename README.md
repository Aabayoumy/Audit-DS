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

### Export-ComputersOS
Exports computer OS details and end-of-support status from Active Directory.
- `-OutputPath`: Path to export the CSV file.
- `-ExportAll`: Exports all computers, not just those nearing or past end-of-support.

### Get-DCs
Lists domain controllers with specific details.

## Usage
1- Download `https://github.com/Aabayoumy/Audit-DS/archive/refs/heads/main.zip` extract and move to Domain Controller.
2- Open PowerShell as Admin and CD to extracted folder.
3- Set execution policy `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force`
4- `Import-Module -Name .\AuditModule -Force`

