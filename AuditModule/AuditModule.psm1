# TODO:
# - separate each function on separate file under public folder (Done)
# - add help to each function (Pending - outside scope of current request)


# Create global variable OutputPath
$Global:DomainName = (Get-ADDomain).Name
$Global:OutputPath = "c:\$DomainName"

# Get the directory of the current script (.psm1 file)
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host $PSScriptRoot 
# Define paths to the private and public function directories
$PrivateFunctionsPath = Join-Path -Path $PSScriptRoot -ChildPath "private"
$PublicFunctionsPath = Join-Path -Path $PSScriptRoot -ChildPath "public"

# Dot-source all .ps1 files in the private directory
Get-ChildItem -Path $PrivateFunctionsPath -Filter *.ps1 | ForEach-Object {
    try {
        . $_.FullName
    } catch {
        Write-Error "Failed to load private function $($_.FullName): $($_.Exception.Message)"
    }
}

# Dot-source all .ps1 files in the public directory
Get-ChildItem -Path $PublicFunctionsPath -Filter *.ps1 | ForEach-Object {
    try {
        . $_.FullName
    } catch {
        Write-Error "Failed to load public function $($_.FullName): $($_.Exception.Message)"
    }
}

# Export only the public functions
Export-ModuleMember -Function Export-NTLMEvents, Export-LDAPEvents, Export-ADInfo, Get-DCs, Export-AdminUsers , Enable-Audit
