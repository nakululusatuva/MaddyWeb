[CmdletBinding()]
param(
    [string] $Directory = "",
    [string] $Path = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($Directory) -and [string]::IsNullOrWhiteSpace($Path)) {
    throw "A private directory or file path is required."
}

$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$allowedSids = @($currentSid.Value, $systemSid.Value)
$rights = [System.Security.AccessControl.FileSystemRights]::FullControl
$allow = [System.Security.AccessControl.AccessControlType]::Allow

function Add-PrivateRules {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemSecurity] $Security,
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.InheritanceFlags] $Inheritance
    )

    $Security.SetOwner($currentSid)
    $Security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($currentSid, $systemSid)) {
        $Security.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                $rights,
                $Inheritance,
                [System.Security.AccessControl.PropagationFlags]::None,
                $allow
            )
        )
    }
}

function Assert-PrivateAcl {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemSecurity] $Security,
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.InheritanceFlags] $ExpectedInheritance
    )

    if (-not $Security.AreAccessRulesProtected) {
        throw "Secret output still inherits access rules."
    }
    $ownerSid = $Security.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    if ($ownerSid -ne $currentSid.Value) {
        throw "Secret output is not owned by the current user."
    }
    $rules = @($Security.Access)
    if ($rules.Count -ne $allowedSids.Count) {
        throw "Secret output does not have exactly two private access rules."
    }
    $seenSids = @()
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
        if (
            $sid -notin $allowedSids `
            -or $rule.AccessControlType -ne $allow `
            -or $rule.IsInherited `
            -or $rule.InheritanceFlags -ne $ExpectedInheritance `
            -or $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
        ) {
            throw "Secret output grants access to an unexpected principal."
        }
        if ($rule.FileSystemRights -ne $rights) {
            throw "Secret output does not grant the required private access."
        }
        $seenSids += $sid
    }
    foreach ($requiredSid in $allowedSids) {
        if ($requiredSid -notin $seenSids) {
            throw "Secret output is missing a required private access rule."
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($Directory)) {
    $directoryPath = [IO.Path]::GetFullPath($Directory)
    $directoryInfo = [IO.DirectoryInfo]::new($directoryPath)
    if ($directoryInfo.Exists) {
        if (($directoryInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Secret output directory must not be a reparse point."
        }
    }
    else {
        $parent = $directoryInfo.Parent
        if ($null -eq $parent -or -not $parent.Exists) {
            throw "Secret output directory parent must exist."
        }
        $security = [System.Security.AccessControl.DirectorySecurity]::new()
        Add-PrivateRules `
            -Security $security `
            -Inheritance (
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
                -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            )
        $directoryInfo.Create($security)
        $directoryInfo.Refresh()
    }
    $directoryInheritance = (
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
        -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    Assert-PrivateAcl `
        -Security (Get-Acl -LiteralPath $directoryInfo.FullName) `
        -ExpectedInheritance $directoryInheritance
}

if (-not [string]::IsNullOrWhiteSpace($Path)) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Secret output must be a regular file."
    }

    $security = [System.Security.AccessControl.FileSecurity]::new()
    Add-PrivateRules `
        -Security $security `
        -Inheritance ([System.Security.AccessControl.InheritanceFlags]::None)
    Set-Acl -LiteralPath $item.FullName -AclObject $security
    Assert-PrivateAcl `
        -Security (Get-Acl -LiteralPath $item.FullName) `
        -ExpectedInheritance ([System.Security.AccessControl.InheritanceFlags]::None)
}
