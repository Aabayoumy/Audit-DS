function Get-SecurityGuidMap {
    [CmdletBinding()]
    param()

    if ($script:SecurityGuidMap) {
        return $script:SecurityGuidMap
    }

    $guidMap = @{
        '00000000-0000-0000-0000-000000000000' = '00000000-0000-0000-0000-000000000000'
        'f30e3bbe-9ff0-11d1-b603-0000f80367c1' = 'User-Change-Password'
    }

    try {
        $rootDse = Get-ADRootDSE -ErrorAction Stop
        $extendedRightsBase = "CN=Extended-Rights,$($rootDse.configurationNamingContext)"

        Get-ADObject -SearchBase $extendedRightsBase -LDAPFilter '(rightsGuid=*)' -Properties displayName, rightsGuid, name -ErrorAction Stop |
            ForEach-Object {
                if ($_.rightsGuid) {
                    $guidKey = ([guid]$_.rightsGuid).Guid.ToLowerInvariant()
                    if (-not $guidMap.ContainsKey($guidKey)) {
                        $guidMap[$guidKey] = if ($_.displayName) { $_.displayName } else { $_.name }
                    }
                }
            }

        Get-ADObject -SearchBase $rootDse.schemaNamingContext -LDAPFilter '(|(objectClass=attributeSchema)(objectClass=classSchema))' -Properties lDAPDisplayName, schemaIDGUID, name -ErrorAction Stop |
            ForEach-Object {
                if ($_.schemaIDGUID) {
                    $guidKey = (New-Object System.Guid (, [byte[]]$_.schemaIDGUID)).Guid.ToLowerInvariant()
                    if (-not $guidMap.ContainsKey($guidKey)) {
                        $guidMap[$guidKey] = if ($_.lDAPDisplayName) { $_.lDAPDisplayName } else { $_.name }
                    }
                }
            }
    } catch {
        Write-Verbose "Unable to build the full AD security GUID map: $($_.Exception.Message)"
    }

    $script:SecurityGuidMap = $guidMap
    return $script:SecurityGuidMap
}

function Get-NormalizedPermissionString {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Permission
    )

    if ([string]::IsNullOrWhiteSpace($Permission)) {
        return ''
    }

    return (($Permission -split ',') |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ } |
        Sort-Object -Unique) -join ', '
}

function Get-SecurityPrincipalInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object]$IdentityReference
    )

    $account = if ($IdentityReference) { [string]$IdentityReference } else { '' }
    $principalSid = $null

    if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
        $principalSid = $IdentityReference.Value
        try {
            $account = $IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $account = $principalSid
        }
    } elseif ($IdentityReference) {
        try {
            $principalSid = $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            $principalSid = $null
        }
    }

    $compareKey = if ($principalSid) { $principalSid } else { $account.ToUpperInvariant() }

    return [PSCustomObject]@{
        Account       = $account
        PrincipalSid  = $principalSid
        PrincipalKey  = $compareKey
    }
}

function Resolve-SecurityGuidName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [guid]$Guid,

        [Parameter(Mandatory = $true)]
        [hashtable]$GuidMap
    )

    if ($Guid -eq [guid]::Empty) {
        return '00000000-0000-0000-0000-000000000000'
    }

    $guidKey = $Guid.Guid.ToLowerInvariant()
    if ($GuidMap.ContainsKey($guidKey)) {
        return $GuidMap[$guidKey]
    }

    return $guidKey
}

function Convert-SddlToSecurityRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sddl,

        [Parameter(Mandatory = $true)]
        [hashtable]$GuidMap
    )

    $descriptor = New-Object System.Security.AccessControl.CommonSecurityDescriptor $true, $true, $Sddl
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        $principalInfo = Get-SecurityPrincipalInfo -IdentityReference $ace.SecurityIdentifier
        $rightsText = [string]([System.Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], [int]$ace.AccessMask))
        $permissionNormalized = Get-NormalizedPermissionString -Permission $rightsText
        $objectTypeGuid = [guid]::Empty
        $inheritedObjectTypeGuid = [guid]::Empty

        if ($ace -is [System.Security.AccessControl.ObjectAce]) {
            if (($ace.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) -ne 0) {
                $objectTypeGuid = $ace.ObjectAceType
            }

            if (($ace.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent) -ne 0) {
                $inheritedObjectTypeGuid = $ace.InheritedObjectAceType
            }
        }

        $objectTypeName = Resolve-SecurityGuidName -Guid $objectTypeGuid -GuidMap $GuidMap
        $inheritedObjectTypeName = Resolve-SecurityGuidName -Guid $inheritedObjectTypeGuid -GuidMap $GuidMap
        $permissionTarget = if ($objectTypeGuid -ne [guid]::Empty) {
            $objectTypeName
        } elseif ($inheritedObjectTypeGuid -ne [guid]::Empty) {
            $inheritedObjectTypeName
        } else {
            '00000000-0000-0000-0000-000000000000'
        }

        [PSCustomObject]@{
            Account             = $principalInfo.Account
            PrincipalSid        = $principalInfo.PrincipalSid
            PrincipalKey        = $principalInfo.PrincipalKey
            AccessControlType   = if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) { 'Allow' } elseif ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessDenied) { 'Deny' } else { [string]$ace.AceQualifier }
            Permission          = $rightsText
            PermissionNormalized = $permissionNormalized
            PermissionTarget    = $permissionTarget
            ObjectType          = $objectTypeName
            InheritedObjectType = $inheritedObjectTypeName
            IsInherited         = [bool]($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited)
            InheritanceType     = [string]$ace.AceFlags
        }
    }
}

function Convert-AdAclToSecurityRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AccessRules,

        [Parameter(Mandatory = $true)]
        [hashtable]$GuidMap
    )

    foreach ($accessRule in $AccessRules) {
        $principalInfo = Get-SecurityPrincipalInfo -IdentityReference $accessRule.IdentityReference
        $rightsText = [string]$accessRule.ActiveDirectoryRights
        $permissionNormalized = Get-NormalizedPermissionString -Permission $rightsText
        $objectTypeName = Resolve-SecurityGuidName -Guid $accessRule.ObjectType -GuidMap $GuidMap
        $inheritedObjectTypeName = Resolve-SecurityGuidName -Guid $accessRule.InheritedObjectType -GuidMap $GuidMap
        $permissionTarget = if ($accessRule.ObjectType -and $accessRule.ObjectType -ne [guid]::Empty) {
            $objectTypeName
        } elseif ($accessRule.InheritedObjectType -and $accessRule.InheritedObjectType -ne [guid]::Empty) {
            $inheritedObjectTypeName
        } else {
            '00000000-0000-0000-0000-000000000000'
        }

        [PSCustomObject]@{
            Account             = $principalInfo.Account
            PrincipalSid        = $principalInfo.PrincipalSid
            PrincipalKey        = $principalInfo.PrincipalKey
            AccessControlType   = [string]$accessRule.AccessControlType
            Permission          = $rightsText
            PermissionNormalized = $permissionNormalized
            PermissionTarget    = $permissionTarget
            ObjectType          = $objectTypeName
            InheritedObjectType = $inheritedObjectTypeName
            IsInherited         = [bool]$accessRule.IsInherited
            InheritanceType     = [string]$accessRule.InheritanceType
        }
    }
}

function Get-AdminSdHolderBaselineRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DomainNetBIOSName,

        [Parameter(Mandatory = $false)]
        [string]$DomainSid
    )

    $baselineCsv = @"
Account,AccessControlType,Permission,PermissionTarget
NT AUTHORITY\Authenticated Users,Allow,GenericRead,00000000-0000-0000-0000-000000000000
NT AUTHORITY\SYSTEM,Allow,GenericAll,00000000-0000-0000-0000-000000000000
BUILTIN\Administrators,Allow,"CreateChild, DeleteChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner",00000000-0000-0000-0000-000000000000
CONTOSO\Domain Admins,Allow,"CreateChild, DeleteChild, Self, WriteProperty, ExtendedRight, GenericRead, WriteDacl, WriteOwner",00000000-0000-0000-0000-000000000000
CONTOSO\Enterprise Admins,Allow,"CreateChild, DeleteChild, Self, WriteProperty, ExtendedRight, GenericRead, WriteDacl, WriteOwner",00000000-0000-0000-0000-000000000000
Everyone,Allow,ExtendedRight,User-Change-Password
NT AUTHORITY\SELF,Allow,"ReadProperty, WriteProperty, ExtendedRight",Private-Information
NT AUTHORITY\SELF,Allow,ExtendedRight,User-Change-Password
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,RAS-Information
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,RAS-Information
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,User-Account-Restrictions
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,General-Information
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,Membership
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,Membership
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,GenericRead,00000000-0000-0000-0000-000000000000
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,GenericRead,00000000-0000-0000-0000-000000000000
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,General-Information
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,User-Logon
BUILTIN\Pre-Windows 2000 Compatible Access,Allow,ReadProperty,User-Account-Restrictions
BUILTIN\Windows Authorization Access Group,Allow,ReadProperty,attributeSchema
BUILTIN\Terminal Server License Servers,Allow,"ReadProperty, WriteProperty",attributeSchema
BUILTIN\Terminal Server License Servers,Allow,"ReadProperty, WriteProperty",Terminal-Server-License-Server
CONTOSO\Cert Publishers,Allow,"ReadProperty, WriteProperty",attributeSchema
"@

    $rows = $baselineCsv | ConvertFrom-Csv
    foreach ($row in $rows) {
        if ($DomainNetBIOSName -and $row.Account -like 'CONTOSO\*') {
            $row.Account = $row.Account -replace '^CONTOSO\\', "$DomainNetBIOSName\\"
        }

        $principalInfo = Get-SecurityPrincipalInfo -IdentityReference $row.Account
        switch -Regex ($row.Account) {
            '^Everyone$' { $principalInfo.PrincipalSid = 'S-1-1-0' }
            '^NT AUTHORITY\\SELF$' { $principalInfo.PrincipalSid = 'S-1-5-10' }
            '^NT AUTHORITY\\Authenticated Users$' { $principalInfo.PrincipalSid = 'S-1-5-11' }
            '^NT AUTHORITY\\SYSTEM$' { $principalInfo.PrincipalSid = 'S-1-5-18' }
            '^BUILTIN\\Administrators$' { $principalInfo.PrincipalSid = 'S-1-5-32-544' }
            '^BUILTIN\\Pre-Windows 2000 Compatible Access$' { $principalInfo.PrincipalSid = 'S-1-5-32-554' }
            '^BUILTIN\\Windows Authorization Access Group$' { $principalInfo.PrincipalSid = 'S-1-5-32-560' }
            '^BUILTIN\\Terminal Server License Servers$' { $principalInfo.PrincipalSid = 'S-1-5-32-561' }
            '^.+\\Domain Admins$' { if ($DomainSid) { $principalInfo.PrincipalSid = "$DomainSid-512" } }
            '^.+\\Cert Publishers$' { if ($DomainSid) { $principalInfo.PrincipalSid = "$DomainSid-517" } }
            '^.+\\Enterprise Admins$' { if ($DomainSid) { $principalInfo.PrincipalSid = "$DomainSid-519" } }
        }

        $principalInfo.PrincipalKey = if ($principalInfo.PrincipalSid) { $principalInfo.PrincipalSid } else { $row.Account.ToUpperInvariant() }

        [PSCustomObject]@{
            Account              = $row.Account
            PrincipalSid         = $principalInfo.PrincipalSid
            PrincipalKey         = $principalInfo.PrincipalKey
            AccessControlType    = $row.AccessControlType
            Permission           = $row.Permission
            PermissionNormalized = Get-NormalizedPermissionString -Permission $row.Permission
            PermissionTarget     = $row.PermissionTarget
        }
    }
}

function Test-ChangePasswordAcePresence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$SecurityRows
    )

    $checks = @(
        [PSCustomObject]@{ Account = 'Everyone'; PrincipalSid = 'S-1-1-0' },
        [PSCustomObject]@{ Account = 'NT AUTHORITY\SELF'; PrincipalSid = 'S-1-5-10' }
    )

    foreach ($check in $checks) {
        $matchingRows = $SecurityRows | Where-Object {
            $_.PrincipalKey -eq $check.PrincipalSid -and
            $_.AccessControlType -eq 'Allow' -and
            $_.PermissionTarget -eq 'User-Change-Password' -and
            $_.PermissionNormalized -match '(^|, )ExtendedRight($|, )'
        }

        [PSCustomObject]@{
            Account        = $check.Account
            PrincipalSid   = $check.PrincipalSid
            AccessControlType = 'Allow'
            Permission     = 'ExtendedRight'
            'PermissionType-or-Attribute' = 'User-Change-Password'
            Exists         = [bool]($matchingRows)
            MatchingRows   = $matchingRows.Count
        }
    }
}

function Compare-SecurityRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$CurrentRows,

        [Parameter(Mandatory = $true)]
        [object[]]$BaselineRows
    )

    $currentIndex = @{}
    foreach ($row in $CurrentRows) {
        $key = '{0}|{1}|{2}|{3}' -f $row.PrincipalKey, $row.AccessControlType.ToUpperInvariant(), $row.PermissionNormalized.ToUpperInvariant(), $row.PermissionTarget.ToUpperInvariant()
        if (-not $currentIndex.ContainsKey($key)) {
            $currentIndex[$key] = [PSCustomObject]@{ Count = 0; Row = $row }
        }
        $currentIndex[$key].Count++
    }

    $baselineIndex = @{}
    foreach ($row in $BaselineRows) {
        $key = '{0}|{1}|{2}|{3}' -f $row.PrincipalKey, $row.AccessControlType.ToUpperInvariant(), $row.PermissionNormalized.ToUpperInvariant(), $row.PermissionTarget.ToUpperInvariant()
        if (-not $baselineIndex.ContainsKey($key)) {
            $baselineIndex[$key] = [PSCustomObject]@{ Count = 0; Row = $row }
        }
        $baselineIndex[$key].Count++
    }

    $diffRows = foreach ($key in (($baselineIndex.Keys + $currentIndex.Keys) | Sort-Object -Unique)) {
        $baselineCount = if ($baselineIndex.ContainsKey($key)) { $baselineIndex[$key].Count } else { 0 }
        $currentCount = if ($currentIndex.ContainsKey($key)) { $currentIndex[$key].Count } else { 0 }

        if ($baselineCount -ne $currentCount) {
            $referenceRow = if ($baselineIndex.ContainsKey($key)) { $baselineIndex[$key].Row } else { $currentIndex[$key].Row }
            [PSCustomObject]@{
                Account                     = $referenceRow.Account
                PrincipalSid                = $referenceRow.PrincipalSid
                AccessControlType           = $referenceRow.AccessControlType
                Permission                  = $referenceRow.Permission
                'PermissionType-or-Attribute' = $referenceRow.PermissionTarget
                BaselineCount               = $baselineCount
                CurrentCount                = $currentCount
                Status                      = if ($baselineCount -gt $currentCount) { 'MissingFromCurrent' } else { 'ExtraInCurrent' }
            }
        }
    }

    $summary = [PSCustomObject]@{
        BaselineRowCount = $BaselineRows.Count
        CurrentRowCount  = $CurrentRows.Count
        MissingRows      = ($diffRows | Where-Object { $_.Status -eq 'MissingFromCurrent' } | Measure-Object).Count
        ExtraRows        = ($diffRows | Where-Object { $_.Status -eq 'ExtraInCurrent' } | Measure-Object).Count
        MatchesBaseline  = [bool](-not $diffRows)
    }

    return [PSCustomObject]@{
        DetailedDiff = $diffRows
        Summary      = $summary
    }
}