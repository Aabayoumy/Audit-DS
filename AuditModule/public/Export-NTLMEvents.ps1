function Export-NTLMEvents {
    [CmdletBinding()]
    param (
        # Define parameters for Audit-NTLM here
        [int]$MaxEvents = 10000
    )
    _AssertAdminPrivileges # Check for admin privileges
    $OutputPath = "$Global:OutputPath\NTLM-$((Get-Date).ToString('ddMMMyy-HHmm'))\"
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    $IgnoredDCs =  _GetIgnoredDCs # Load ignored DCs
    foreach ($DC in (Get-ADDomainController -Filter *).HostName | Where-Object { $_ -notin $IgnoredDCs }){
        $OutputFile = "$OutputPath\$($DC).csv"
        Write-Host "[$($DC)] Searching log"
        $Events = Get-WinEvent -ComputerName $DC -Logname security -MaxEvents $MaxEvents  -FilterXPath "Event[System[(EventID=4624)]]and (Event[EventData[Data[@Name='LmPackageName']='NTLM V2']] or Event[EventData[Data[@Name='LmPackageName']='NTLM V1']])" | Select-Object `
        @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
        @{Label='UserName';Expression={$_.Properties[5].Value}},
        @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
        @{Label='WorkstationIP';Expression={$_.Properties[18].Value}},
        @{Label='LogonType';Expression={$_.properties[8].value}},
        @{Label='LmPackageName';Expression={$_.properties[14].value}},
        @{Label='ImpersonationLevel';Expression={$_.properties[20].value}}
        $Events | Export-Csv $OutputFile -NoTypeInformation
        # Filter for NTLM V1 events excluding ANONYMOUS LOGON
        $NtlmV1Events = $Events | Where-Object { $_.LmPackageName -eq 'NTLM V1' -and $_.UserName -ne 'ANONYMOUS LOGON' }
        $NtlmV1Count = $NtlmV1Events.Count
        # Update Write-Host to include the count
        Write-Host "[$($DC)] $NtlmV1Count NTLMv1 Events"
    }
}
