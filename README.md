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
- Also runs `Export-UserSecurity` automatically and writes its files into the same output folder.

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

### Export-SMB1Events

Exports SMB1 access events from the local server.

- `-MaxEvents`: Maximum number of events to retrieve (default: 10000).
- `-Days`: Number of days back from the current date to limit events (default: 7).

### Export-RC4Tickets

Exports Kerberos service-ticket events (Event ID 4769) that use RC4 (`TicketEncryptionType = 0x17`) from all domain controllers.

- `-DaysBack`: Number of days of Security log history to search (default: `1`).
- `-CsvPath`: Full path for CSV output (default: `$Global:OutputPath\RC4-4769-<date>.csv`).
- Includes Domain Controller, event time, target username, and service name.

### Export-ComputersOS

Exports computer OS details and end-of-support status from Active Directory.

- `-OutputPath`: Path to export the CSV file.
- `-ExportAll`: Exports all computers, not just those nearing or past end-of-support.

### Export-UserSecurity

Exports the default security descriptor for the AD `user` schema class and the current `AdminSDHolder` ACL.

- `-OutputPath`: Path where the security CSV and SDDL files will be written.
- Exports the parsed user class default security descriptor to CSV.
- Checks whether `Everyone` and `NT AUTHORITY\SELF` have the `User-Change-Password` right.
- Exports the current `AdminSDHolder` ACL, the expected baseline, a detailed diff CSV, and a summary CSV.

#### Export-UserSecurity output files

- `UserClass-DefaultSecurityDescriptor.txt`: Raw `defaultSecurityDescriptor` SDDL value from the AD `user` class in schema.
- `UserClass-DefaultSecurityDescriptor.csv`: Parsed ACE rows from the user class default descriptor.
- `UserClass-ChangePasswordCheck.csv`: Validation result for the required `User-Change-Password` ACEs for `Everyone` and `NT AUTHORITY\SELF`.
- `AdminSDHolder-SDDL.txt`: Raw SDDL for current `CN=AdminSDHolder,CN=System,<domainDN>` permissions.
- `AdminSDHolder-CurrentAccess.csv`: Parsed current AdminSDHolder ACL entries.
- `AdminSDHolder-Baseline.csv`: Baseline ACL entries used for comparison.
- `AdminSDHolder-BaselineDiff.csv`: Detailed ACE-level differences between current ACL and baseline.
- `AdminSDHolder-BaselineSummary.csv`: High-level comparison summary with match status and counts.

#### How to run

- Run directly: `Export-UserSecurity -OutputPath C:\AuditOutput\UserSecurity`
- Run as part of full collection: `Export-ADInfo` (calls `Export-UserSecurity` automatically and saves files in the same output folder)

### Get-LdapServerCertificate

Gets the certificate presented by a host during a TLS handshake (default LDAPS port 636).

- `-HostName` (or `-DCName`): Target host/DC. If omitted, the function automatically uses the domain PDC emulator and prints which DC was used.
- `-Port`: TLS port to connect to (default: `636`).
- `-ExportCrt`: If specified, exports the certificate to the current folder as `<DC>-LDAPS.cer`.

### Download-PingCastle

Downloads and extracts PingCastle to the module folder.

- `-Tag`: PingCastle release tag to download. Defaults to `$Global:PingCastleTag` (currently `3.5.0.44`).
- `-Force`: Re-downloads and re-extracts even if `PingCastle.exe` already exists.
- Downloads from GitHub release assets using `PingCastle_<tag>.zip`.

### Run-PingCastle

Runs PingCastle in command-line mode and recommends the silent healthcheck command.

- If `PingCastle.exe` is not found in the module folder, it automatically calls `Download-PingCastle`.
- Validates PingCastle command-line switches using `PingCastle.exe --help`.
- Recommended silent command: `PingCastle.exe --healthcheck --server <domain>`.
- `-Server`: Domain to scan. If omitted, the current AD domain DNS name is used.
- `-OutputPath`: Optional working folder where PingCastle runs before results are moved.
- After execution, generated `*.html` and `*.xml` files are moved to `$Global:OutputPath\<yyyy-MM-dd>` and that folder is opened.

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
