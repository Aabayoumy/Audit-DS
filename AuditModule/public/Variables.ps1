$Global:DomainName = (Get-ADDomain).Name
$Global:OutputPath = "c:\$DomainName"

Write-Host "Output Path: $Global:OutputPath" -ForegroundColor Green
