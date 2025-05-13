# This module is designed to be used with PowerShell 5.1 and later.

# Write-Host $PSScriptRoot 
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
Export-ModuleMember -Function Export-NTLMEvents, Export-LDAPEvents, Export-ADInfo, Get-DCs, Export-AdminUsers, Enable-Audit, Export-ComputersOS, Set-LogSize
