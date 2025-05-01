# Private function to load ignored DCs from JSON
function _GetIgnoredDCs {
    param(

    )

    $IgnoredDCs = @() # Initialize as an empty array within the function scope
    try {
        $JsonPath = Join-Path -Path $PSScriptRoot  -ChildPath "AuditDS.json"
        # Check if the JSON file exists before trying to read it
        if (Test-Path -Path $JsonPath) {
            $IgnoredDCsObject = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json
            # Ensure the property exists before trying to access it
            if ($IgnoredDCsObject -and $IgnoredDCsObject.PSObject.Properties.Name -contains 'ignored-DCs') {
                $IgnoredDCs = $IgnoredDCsObject.'ignored-DCs'
                # Check if the array is not null and not empty
                if ($IgnoredDCs -and $IgnoredDCs.Count -gt 0) {
                    Write-Host "Ignoring the following DCs: $($IgnoredDCs -join ', ')"
                }
            } else {
                # Handle case where JSON is valid but doesn't contain 'ignored-DCs' or is empty/malformed
                # $IgnoredDCs is already @()
            }
        } else {
            Write-Warning "AuditDS.json not found at '$JsonPath'. No DCs will be ignored."
            # $IgnoredDCs is already @()
        }
    } catch {
        Write-Warning "Could not load ignored DCs from AuditDS.json. $($_.Exception.Message)"
        # $IgnoredDCs is already @()
    }
    # Return the array
    return $IgnoredDCs
}
