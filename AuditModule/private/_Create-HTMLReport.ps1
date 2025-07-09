function Export-Report {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSObject[]]$InputObject,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [string]$Title,
        
        [Parameter(Mandatory=$false)]
        [string]$DomainInfo
    )

    begin {
        $reportFile = Join-Path $OutputPath "report.html"
        Write-Host "Creating HTML report at $reportFile" -ForegroundColor Cyan
        Write-Host $allData.Count
        # Define CSS styles
        $css = @"
<link href='https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap' rel='stylesheet'>
<style>
/* Your full CSS styles here */
</style>
"@

        # Initialize data collection array
        $script:allData = @()
        
        # Create directory if needed
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        # Initialize report if file doesn't exist
        if (-not (Test-Path $reportFile)) {
            $domainName = try { (Get-ADDomain).Name } catch { "Unknown Domain" }
            $currentDate = Get-Date -Format 'yyyy-MM-dd'
            
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Domain Report</title>
    $css
</head>
<body>
    <div class="container">
        <div class="header">
            <a href="#toc">Table of Contents</a>
        </div>
        <h1>$domainName - $currentDate</h1>
"@
            if ($DomainInfo) {
                $html += @"
        <h2>Domain Information</h2>
        <div>$DomainInfo</div>
"@
            }
            
            $html += @"
        <h2 id="toc">Table of Contents</h2>
        <ul id="toc-list">
            <!-- TOC_ENTRIES -->
        </ul>
"@
            $html | Set-Content -Path $reportFile
        }
    }

    process {
        # Collect all input objects
        foreach ($item in $InputObject) {
            $script:allData += $item
        }
    }

    end {
        # Exit if no data to process
        if (-not $script:allData -or $script:allData.Count -eq 0) {
            Write-Warning "No data received for report section: $Title"
            return
        }
        
        # Generate HTML table
        $tableHtml = $script:allData | ConvertTo-Html -Fragment
        
        # Generate section ID from title
        $sectionId = ($Title -replace '[^a-zA-Z0-9]', '_').ToLower()
        
        # Read existing content
        $content = Get-Content $reportFile -Raw
        
        # Update Table of Contents
        $tocEntry = "<li><a href='#$sectionId'>$Title</a></li>"
        if ($content -match '<ul id="toc-list">') {
            $content = $content -replace '(?s)(<ul id="toc-list">.*?)(<!-- TOC_ENTRIES -->)', "`$1$tocEntry`n`$2"
        }
        
        # Append new section
        $newSection = @"
        <h2 id="$sectionId">$Title</h2>
        <div class="table-container">
            $tableHtml
        </div>
        <p><a href="#toc">Back to Table of Contents</a></p>
"@
        $content = $content -replace '</body>', "$newSection</body>"
        
        # Save updated content
        $content | Set-Content -Path $reportFile
        Write-Host "Added report section: $Title" -ForegroundColor Green
    }
}
