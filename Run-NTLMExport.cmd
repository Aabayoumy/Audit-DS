powershell.exe -Command "Set-ExecutionPolicy -Scope Process -ChangeExecutionPolicy -Force Bypass; Import-Module .\AuditModule\AuditModule.psd1; Export-NTLMEvents"
