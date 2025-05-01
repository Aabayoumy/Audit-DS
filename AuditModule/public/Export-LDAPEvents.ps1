function Export-LDAPEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-LDAP here
        [int]$MaxEvents = 10000
    )
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\LDAP-$($((Get-Date).ToString('ddMMMyy-HHmm')))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $IgnoredDCs =  _GetIgnoredDCs # Load ignored DCs
    # Implementation for Audit-LDAP
    foreach ($DC in (Get-ADDomainController -Filter *).HostName | Where-Object { $_ -notin $IgnoredDCs }){
        $OutputFile = "$OutputPath\$($DC)_$((Get-Date).ToString('dd-MMMM-yyyy')).csv"
        $Events = Get-WinEvent -Logname "Directory Service" -FilterXPath "Event[System[(EventID=2889)]]" | Select-Object @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},   @{Label='SourceIP';Expression={$_.Properties[0].Value}},    @{Label='User';Expression={$_.Properties[1].Value}}
        $Events | Export-Csv $OutputFile -NoTypeInformation
    }
}
