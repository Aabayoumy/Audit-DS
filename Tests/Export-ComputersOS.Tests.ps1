# Tests for Export-ComputersOS.ps1

BeforeEach {
    # Mock Get-Module to control its output
    Mock Get-Module {
        param($ListAvailable, $Name)
        if ($Name -eq 'ActiveDirectory') {
            # Simulate module not found by default
            return $null
        }
        # Add other modules here if needed for future tests
    }
    # Mock Test-Path to control file existence checks
    Mock Test-Path {
        param($Path)
        # Simulate data.json not found by default
        return $false
    }
    # Mock Get-Content and ConvertFrom-Json for data.json
    Mock Get-Content {
        param($Path, $Raw)
        # Simulate invalid JSON by default
        throw "Simulated JSON parsing error"
    }
    Mock ConvertFrom-Json {
        param($InputObject)
        # This mock should ideally not be hit if Get-Content throws an error,
        # but included for completeness if Get-Content is mocked to return valid JSON
        throw "Simulated JSON conversion error"
    }
    # Mock Get-ADComputer
    Mock Get-ADComputer {
        param($Filter, $Properties, $ErrorAction)
        # Simulate no computers found by default
        return @()
    }
    # Mock Export-Csv
    Mock Export-Csv {
        param($Path, $NoTypeInformation, $Encoding, $ErrorAction)
        # Do nothing, just capture parameters if needed
    }
    # Mock Write-Error and Write-Host to capture output
Mock Write-Error { param($Message) Write-Output "ERROR: $Message" }
Mock Write-Host { param($Message) Write-Output "HOST: $Message" }
}

Describe "Export-ComputersOS" {
    It "Should write an error if ActiveDirectory module is not available" {
        # Arrange
        Mock Get-Module {
            param($ListAvailable, $Name)
            if ($Name -eq 'ActiveDirectory') {
                return $null # Simulate module not found
            }
        }

        # Act
        Export-ComputersOS

        # Assert
        Assert-MockCalled Write-Error -Exactly 1 -ParameterFilter {
            $Message -like "*Active Directory PowerShell module is not installed or available*"
        }
    }

    It "Should write an error and return if data.json is not found" {
        # Arrange
        Mock Get-Module {
            param($ListAvailable, $Name)
            if ($Name -eq 'ActiveDirectory') {
                # Simulate module found
                return [PSCustomObject]@{ Name = 'ActiveDirectory' }
            }
        }
        Mock Test-Path {
            param($Path)
            # Simulate data.json not found
            return $false
        }

        # Act
        Export-ComputersOS

        # Assert
        Assert-MockCalled Write-Error -Exactly 1 -ParameterFilter {
            $Message -like "*JSON file not found at*"
        }
        # Add assertion to check for early return if possible,
        # e.g., by checking if Get-ADComputer was not called
        Assert-MockCalled Get-ADComputer -Times 0
    }

    It "Should write an error and return if data.json is invalid" {
        # Arrange
        Mock Get-Module {
            param($ListAvailable, $Name)
            if ($Name -eq 'ActiveDirectory') {
                # Simulate module found
                return [PSCustomObject]@{ Name = 'ActiveDirectory' }
            }
        }
        Mock Test-Path {
            param($Path)
            # Simulate data.json found
            return $true
        }
        Mock Get-Content {
            param($Path, $Raw)
            # Simulate invalid JSON content
            return "{ invalid json }"
        }
        # Mock ConvertFrom-Json to simulate parsing error
        Mock ConvertFrom-Json {
            param($InputObject)
            throw "ConvertFrom-Json : Invalid JSON"
        }

        # Act
        Export-ComputersOS

        # Assert
        Assert-MockCalled Write-Error -Exactly 1 -ParameterFilter {
            $Message -like "*Failed to load or parse JSON file*"
        }
        # Assert that Get-ADComputer was not called
        Assert-MockCalled Get-ADComputer -Times 0
    }

    It "Should call Get-ADComputer with correct parameters when module and data.json are valid" {
        # Arrange
        Mock Get-Module {
            param($ListAvailable, $Name)
            if ($Name -eq 'ActiveDirectory') {
                # Simulate module found
                return [PSCustomObject]@{ Name = 'ActiveDirectory' }
            }
        }
        Mock Test-Path {
            param($Path)
            # Simulate data.json found
            return $true
        }
        Mock Get-Content {
            param($Path, $Raw)
            # Simulate valid JSON content
            return '{ "windows_versions": [] }'
        }
        Mock ConvertFrom-Json {
            param($InputObject)
            # Simulate successful JSON conversion
            return [PSCustomObject]@{ windows_versions = @() }
        }
        # Arrange for Get-ADComputer to be called
        Mock Get-ADComputer {
            param($Filter, $Properties, $ErrorAction)
            # Return an empty array to avoid further processing errors
            return @()
        }

        # Act
        Export-ComputersOS

        # Assert
        Assert-MockCalled Get-ADComputer -Exactly 1 -ParameterFilter {
            $Filter -eq "*" -and
            $Properties -contains "Name" -and
            $Properties -contains "OperatingSystem" -and
            $Properties -contains "OperatingSystemVersion" -and
            $Properties -contains "Enabled" -and
            $Properties -contains "lastLogonTimestamp" -and
            $ErrorAction -eq "Stop"
        }
    }

    It "Should correctly extract build number from OperatingSystemVersion" {
        # Arrange
        $mockComputers = @(
            [PSCustomObject]@{
                Name                   = "Computer1"
                OperatingSystem        = "Windows Server 2019 Standard"
                OperatingSystemVersion = "10.0 (17763)"
                Enabled                = $true
                lastLogonTimestamp     = 0 # Mock value
            },
            [PSCustomObject]@{
                Name                   = "Computer2"
                OperatingSystem        = "Windows 10 Pro"
                OperatingSystemVersion = "10.0 (19045)"
                Enabled                = $true
                lastLogonTimestamp     = 0 # Mock value
            },
            [PSCustomObject]@{
                Name                   = "Computer3"
                OperatingSystem        = "Windows 7 Professional"
                OperatingSystemVersion = "6.1 (7601)" # Older format
                Enabled                = $true
                lastLogonTimestamp     = 0 # Mock value
            },
            [PSCustomObject]@{
                Name                   = "Computer4"
                OperatingSystem        = "Linux"
                OperatingSystemVersion = "Ubuntu 20.04" # No build number
                Enabled                = $true
                lastLogonTimestamp     = 0 # Mock value
            }
        )
        Mock Get-Module {
            param($ListAvailable, $Name)
            if ($Name -eq 'ActiveDirectory') { return [PSCustomObject]@{ Name = 'ActiveDirectory' } }
        }
        Mock Test-Path { param($Path) return $true } # Simulate data.json found
        Mock Get-Content { param($Path, $Raw) return '{ "windows_versions": [] }' } # Simulate valid JSON
        Mock ConvertFrom-Json { param($InputObject) return [PSCustomObject]@{ windows_versions = @() } } # Simulate successful conversion
        Mock Get-ADComputer { param($Filter, $Properties, $ErrorAction) return $mockComputers }
        Mock Export-Csv { param($Path, $NoTypeInformation, $Encoding, $ErrorAction) { $script:ExportedResults = $input } } # Capture exported data

        # Act
        Export-ComputersOS

        # Assert
        $script:ExportedResults | Should -Not -BeNullOrEmpty
        $script:ExportedResults.Count | Should -Be $mockComputers.Count
        $script:ExportedResults[0].BuildNumber | Should -Be "17763"
        $script:ExportedResults[1].BuildNumber | Should -Be "19045"
        $script:ExportedResults[2].BuildNumber | Should -Be "7601"
        $script:ExportedResults[3].BuildNumber | Should -Be $null # No build number expected
    }

    It "Should correctly determine support status based on build number and current date" {
        # Arrange
        $mockComputers = @(
            [PSCustomObject]@{
                Name                   = "Computer1"
                OperatingSystemVersion = "10.0 (17763)" # In extended support (example date)
                lastLogonTimestamp     = 0
            },
            [PSCustomObject]@{
                Name                   = "Computer2"
                OperatingSystemVersion = "10.0 (19045)" # In support (example date)
                lastLogonTimestamp     = 0
            },
            [PSCustomObject]@{
                Name                   = "Computer3"
                OperatingSystemVersion = "6.1 (7601)" # Out of support (example date)
                lastLogonTimestamp     = 0
            },
            [PSCustomObject]@{
                Name                   = "Computer4"
                OperatingSystemVersion = "10.0 (99999)" # Unknown build number
                lastLogonTimestamp     = 0
            }
        )
        $mockOsData = @{
            windows_versions = @(
                @{ build_number = "17763"; end_of_mainstream_support = "2024-01-01"; end_of_extended_support = "2025-01-01" }, # Extended support
                @{ build_number = "19045"; end_of_mainstream_support = "2026-01-01"; end_of_extended_support = "2027-01-01" }, # In support
                @{ build_number = "7601"; end_of_mainstream_support = "2015-01-01"; end_of_extended_support = "2020-01-01" }  # Out of support
            )
        }
        # Mock Get-Date to control the "current date" for status determination
        Mock Get-Date { return [datetime]"2025-06-01" } # Set current date for testing

        Mock Get-Module { param($ListAvailable, $Name) { if ($Name -eq 'ActiveDirectory') { return [PSCustomObject]@{ Name = 'ActiveDirectory' } } } }
        Mock Test-Path { param($Path) { return $true } } # Simulate data.json found
        Mock Get-Content { param($Path, $Raw) { return ($mockOsData | ConvertTo-Json) } } # Simulate valid JSON
        Mock ConvertFrom-Json { param($InputObject) { return $mockOsData } } # Simulate successful conversion
        Mock Get-ADComputer { param($Filter, $Properties, $ErrorAction) { return $mockComputers } }
        Mock Export-Csv { param($Path, $NoTypeInformation, $Encoding, $ErrorAction) { $script:ExportedResults = $input } } # Capture exported data

        # Act
        Export-ComputersOS

        # Assert
        $script:ExportedResults | Should -Not -BeNullOrEmpty
        $script:ExportedResults.Count | Should -Be $mockComputers.Count
        ($script:ExportedResults | Where-Object Name -eq "Computer1").Status | Should -Be "in extended support"
        ($script:ExportedResults | Where-Object Name -eq "Computer2").Status | Should -Be "in support"
        ($script:ExportedResults | Where-Object Name -eq "Computer3").Status | Should -Be "Out of support"
        ($script:ExportedResults | Where-Object Name -eq "Computer4").Status | Should -Be "Unknown" # Unknown build number
    }

    It "Should filter results to 'end of support' or 'in extended support' when ExportAll is not specified" {
        # Arrange
        $mockComputers = @(
            [PSCustomObject]@{ Name = "Computer1"; OperatingSystemVersion = "10.0 (17763)"; lastLogonTimestamp = 0 }, # In extended support
            [PSCustomObject]@{ Name = "Computer2"; OperatingSystemVersion = "10.0 (19045)"; lastLogonTimestamp = 0 }, # In support
            [PSCustomObject]@{ Name = "Computer3"; OperatingSystemVersion = "6.1 (7601)"; lastLogonTimestamp = 0 },  # Out of support
            [PSCustomObject]@{ Name = "Computer4"; OperatingSystemVersion = "10.0 (99999)"; lastLogonTimestamp = 0 }  # Unknown
        )
        $mockOsData = @{
            windows_versions = @(
                @{ build_number = "17763"; end_of_mainstream_support = "2024-01-01"; end_of_extended_support = "2025-01-01" }, # Extended support
                @{ build_number = "19045"; end_of_mainstream_support = "2026-01-01"; end_of_extended_support = "2027-01-01" }, # In support
                @{ build_number = "7601"; end_of_mainstream_support = "2015-01-01"; end_of_extended_support = "2020-01-01" }  # Out of support
            )
        }
        Mock Get-Date { return [datetime]"2025-06-01" } # Set current date for testing

        Mock Get-Module { param($ListAvailable, $Name) { if ($Name -eq 'ActiveDirectory') { return [PSCustomObject]@{ Name = 'ActiveDirectory' } } } }
        Mock Test-Path { param($Path) { return $true } } # Simulate data.json found
        Mock Get-Content { param($Path, $Raw) { return ($mockOsData | ConvertTo-Json) } } # Simulate valid JSON
        Mock ConvertFrom-Json { param($InputObject) { return $mockOsData } } # Simulate successful conversion
        Mock Get-ADComputer { param($Filter, $Properties, $ErrorAction) { return $mockComputers } }
        Mock Export-Csv { param($Path, $NoTypeInformation, $Encoding, $ErrorAction) { $script:ExportedResults = $input } } # Capture exported data

        # Act
        Export-ComputersOS

        # Assert
        $script:ExportedResults | Should -Not -BeNullOrEmpty
        $script:ExportedResults.Count | Should -Be 2 # Should only include Computer1 (extended) and Computer3 (out of support)
        $script:ExportedResults.Name | Should -Contain "Computer1"
        $script:ExportedResults.Name | Should -Contain "Computer3"
        $script:ExportedResults.Name | Should -Not -Contain "Computer2"
        $script:ExportedResults.Name | Should -Not -Contain "Computer4"
    }

    It "Should export all results when ExportAll is specified" {
        # Arrange
        $mockComputers = @(
            [PSCustomObject]@{ Name = "Computer1"; OperatingSystemVersion = "10.0 (17763)"; lastLogonTimestamp = 0 }, # In extended support
            [PSCustomObject]@{ Name = "Computer2"; OperatingSystemVersion = "10.0 (19045)"; lastLogonTimestamp = 0 }, # In support
            [PSCustomObject]@{ Name = "Computer3"; OperatingSystemVersion = "6.1 (7601)"; lastLogonTimestamp = 0 },  # Out of support
            [PSCustomObject]@{ Name = "Computer4"; OperatingSystemVersion = "10.0 (99999)"; lastLogonTimestamp = 0 }  # Unknown
        )
        $mockOsData = @{
            windows_versions = @(
                @{ build_number = "17763"; end_of_mainstream_support = "2024-01-01"; end_of_extended_support = "2025-01-01" }, # Extended support
                @{ build_number = "19045"; end_of_mainstream_support = "2026-01-01"; end_of_extended_support = "2027-01-01" }, # In support
                @{ build_number = "7601"; end_of_mainstream_support = "2015-01-01"; end_of_extended_support = "2020-01-01" }  # Out of support
            )
        }
        Mock Get-Date { return [datetime]"2025-06-01" } # Set current date for testing

        Mock Get-Module { param($ListAvailable, $Name) { if ($Name -eq 'ActiveDirectory') { return [PSCustomObject]@{ Name = 'ActiveDirectory' } } } }
        Mock Test-Path { param($Path) { return $true } } # Simulate data.json found
        Mock Get-Content { param($Path, $Raw) { return ($mockOsData | ConvertTo-Json) } } # Simulate valid JSON
        Mock ConvertFrom-Json { param($InputObject) { return $mockOsData } } # Simulate successful conversion
        Mock Get-ADComputer { param($Filter, $Properties, $ErrorAction) { return $mockComputers } }
        Mock Export-Csv { param($Path, $NoTypeInformation, $Encoding, $ErrorAction) { $script:ExportedResults = $input } } # Capture exported data

        # Act
        Export-ComputersOS -ExportAll

        # Assert
        $script:ExportedResults | Should -Not -BeNullOrEmpty
        $script:ExportedResults.Count | Should -Be $mockComputers.Count # Should include all computers
        $script:ExportedResults.Name | Should -Contain "Computer1"
        $script:ExportedResults.Name | Should -Contain "Computer2"
        $script:ExportedResults.Name | Should -Contain "Computer3"
        $script:ExportedResults.Name | Should -Contain "Computer4"
    }

    It "Should call Export-Csv with correct parameters" {
        # Arrange
        $mockComputers = @(
            [PSCustomObject]@{ Name = "Computer1"; OperatingSystemVersion = "10.0 (17763)"; lastLogonTimestamp = 0 }
        )
        $mockOsData = @{
            windows_versions = @(
                @{ build_number = "17763"; end_of_mainstream_support = "2024-01-01"; end_of_extended_support = "2025-01-01" }
            )
        }
        Mock Get-Date { return [datetime]"2025-06-01" }

        Mock Get-Module { param($ListAvailable, $Name) { if ($Name -eq 'ActiveDirectory') { return [PSCustomObject]@{ Name = 'ActiveDirectory' } } } }
        Mock Test-Path { param($Path) { return $true } }
        Mock Get-Content { param($Path, $Raw) { return ($mockOsData | ConvertTo-Json) } }
        Mock ConvertFrom-Json { param($InputObject) { return $mockOsData } }
        Mock Get-ADComputer { param($Filter, $Properties, $ErrorAction) { return $mockComputers } }
        # Mock Export-Csv to capture parameters
        Mock Export-Csv {
            param($Path, $NoTypeInformation, $Encoding, $ErrorAction)
            $script:ExportCsvPath = $Path
            $script:ExportCsvNoTypeInformation = $NoTypeInformation
            $script:ExportCsvEncoding = $Encoding
            $script:ExportCsvErrorAction = $ErrorAction
        }
        # Mock New-Item to prevent actual directory creation
        Mock New-Item { param($Path, $ItemType, $Force) { } }


        # Act
        Export-ComputersOS -OutputPath "C:\Temp\AuditReport"

        # Assert
        $script:ExportCsvPath | Should -Match "C:\\Temp\\AuditReport\\Computers_OS_Support\d{6}-\d{4}\.csv"
        $script:ExportCsvNoTypeInformation | Should -Be $true
        $script:ExportCsvEncoding | Should -Be "UTF8"
        $script:ExportCsvErrorAction | Should -Be "Stop"
    }
}
