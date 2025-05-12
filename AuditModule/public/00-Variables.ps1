$Global:DomainName = (Get-ADDomain).Name
$Global:OutputPath = "c:\$DomainName"

Write-Host "Domain: $Global:DomainName" -ForegroundColor Green
Write-Host "Output Path: $Global:OutputPath" -ForegroundColor Green
