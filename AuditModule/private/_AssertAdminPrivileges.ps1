# Private function to check for administrative privileges
function AssertAdminPrivileges {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Throw "This script requires administrative privileges to run. Please re-run PowerShell as Administrator."
        exit 1 # Terminate the script immediately
    }
}
