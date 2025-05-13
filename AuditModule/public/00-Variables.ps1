$Global:DomainName = (Get-ADDomain).Name
$Global:OutputPath = "c:\$DomainName"
# Get the directory of the current script (.psm1 file)
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Domain: $Global:DomainName" -ForegroundColor Green
Write-Host "Output Path: $Global:OutputPath" -ForegroundColor Green
