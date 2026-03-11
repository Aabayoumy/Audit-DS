function Export-UserSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'Path to store the exported files.')]
        [string]$OutputPath,
        [switch]$Help,
        [switch]$h
    )

    if ($Help -or $h -or ($Args.Count -gt 0 -and $Args[0] -notin @('-h', '-help', '-OutputPath'))) {
        Write-Host 'Exports the default user schema security descriptor and compares AdminSDHolder permissions.'
        Write-Host '-OutputPath: Path where the security export files will be written.'
        return
    }

    AssertAdminPrivileges

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error 'Active Directory module is not installed. Please install the RSAT tools.'
        return
    }

    if (-not $OutputPath) {
        $OutputPath = "$Global:OutputPath\UserSecurity-$((Get-Date).ToString('ddMMMyy-HHmm'))"
    }

    $null = New-Item -Path $OutputPath -ItemType Directory -Force

    $domain = Get-ADDomain
    $rootDse = Get-ADRootDSE
    $guidMap = Get-SecurityGuidMap

    $userClass = Get-ADObject -SearchBase $rootDse.schemaNamingContext -LDAPFilter '(&(objectClass=classSchema)(lDAPDisplayName=user))' -Properties defaultSecurityDescriptor, distinguishedName, lDAPDisplayName -ErrorAction Stop
    if (-not $userClass.defaultSecurityDescriptor) {
        Write-Error 'The user class does not expose a defaultSecurityDescriptor value.'
        return
    }

    $userDescriptorPath = "$OutputPath\UserClass-DefaultSecurityDescriptor.txt"
    $userPermissionsPath = "$OutputPath\UserClass-DefaultSecurityDescriptor.csv"
    $changePasswordCheckPath = "$OutputPath\UserClass-ChangePasswordCheck.csv"
    $adminSdHolderSddlPath = "$OutputPath\AdminSDHolder-SDDL.txt"
    $adminSdHolderCurrentPath = "$OutputPath\AdminSDHolder-CurrentAccess.csv"
    $adminSdHolderBaselinePath = "$OutputPath\AdminSDHolder-Baseline.csv"
    $adminSdHolderDiffPath = "$OutputPath\AdminSDHolder-BaselineDiff.csv"
    $adminSdHolderSummaryPath = "$OutputPath\AdminSDHolder-BaselineSummary.csv"

    Set-Content -Path $userDescriptorPath -Value $userClass.defaultSecurityDescriptor -Encoding UTF8

    $userSecurityRows = @(Convert-SddlToSecurityRows -Sddl $userClass.defaultSecurityDescriptor -GuidMap $guidMap)
    $userSecurityRows |
        Select-Object Account, PrincipalSid, AccessControlType, Permission, @{Name='PermissionType-or-Attribute'; Expression = { $_.PermissionTarget } }, ObjectType, InheritedObjectType, IsInherited, InheritanceType |
        Export-Csv -Path $userPermissionsPath -NoTypeInformation -Encoding UTF8

    $changePasswordChecks = @(Test-ChangePasswordAcePresence -SecurityRows $userSecurityRows)
    $changePasswordChecks | Export-Csv -Path $changePasswordCheckPath -NoTypeInformation -Encoding UTF8

    $adminSdHolderDn = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
    $adminSdHolderAcl = Get-Acl "AD:\$adminSdHolderDn"
    $adminSdHolderSddl = $adminSdHolderAcl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
    Set-Content -Path $adminSdHolderSddlPath -Value $adminSdHolderSddl -Encoding UTF8

    $adminSdHolderRows = @(Convert-AdAclToSecurityRows -AccessRules $adminSdHolderAcl.Access -GuidMap $guidMap)
    $adminSdHolderRows |
        Select-Object Account, PrincipalSid, AccessControlType, Permission, @{Name='PermissionType-or-Attribute'; Expression = { $_.PermissionTarget } }, ObjectType, InheritedObjectType, IsInherited, InheritanceType |
        Export-Csv -Path $adminSdHolderCurrentPath -NoTypeInformation -Encoding UTF8

    $baselineRows = @(Get-AdminSdHolderBaselineRows -DomainNetBIOSName $domain.NetBIOSName -DomainSid $domain.DomainSID.Value)
    $baselineRows |
        Select-Object Account, PrincipalSid, AccessControlType, Permission, @{Name='PermissionType-or-Attribute'; Expression = { $_.PermissionTarget } } |
        Export-Csv -Path $adminSdHolderBaselinePath -NoTypeInformation -Encoding UTF8

    $comparison = Compare-SecurityRows -CurrentRows $adminSdHolderRows -BaselineRows $baselineRows
    @($comparison.DetailedDiff) | Export-Csv -Path $adminSdHolderDiffPath -NoTypeInformation -Encoding UTF8
    @($comparison.Summary) | Export-Csv -Path $adminSdHolderSummaryPath -NoTypeInformation -Encoding UTF8

    [PSCustomObject]@{
        OutputPath                  = $OutputPath
        UserSecurityFile            = $userPermissionsPath
        ChangePasswordCheckFile     = $changePasswordCheckPath
        AdminSDHolderCurrentFile    = $adminSdHolderCurrentPath
        AdminSDHolderDiffFile       = $adminSdHolderDiffPath
        AdminSDHolderSummaryFile    = $adminSdHolderSummaryPath
        AdminSDHolderMatchesBaseline = $comparison.Summary.MatchesBaseline
    }
}