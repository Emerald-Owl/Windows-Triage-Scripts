# For Powershell v4+
# Quick, required admin

function Get-RunningProcesses{
    get-process -IncludeUserName | 
    Where-Object HasExited -eq $False | 
    sort-object StartTime -Descending |
    select-object StartTime, ID, ProcessName, UserName
}


# More verbose, For Powershell v4+
function Get-UserProcessesExt{
    get-process -IncludeUserName | 
    sort-object StartTime -Descending |
    select-object StartTime, ID, ProcessName, UserName, CommandLine, HasExited 
}


# For PowerShell < v4
function Get-UserProcessesLegacy{
    $processes = Get-WmiObject Win32_Process
    $processes | ForEach-Object {
        $processUser = $_.GetOwner()
        [PSCustomObject]@{
            'ProcessName' = $_.Name;
            'ProcessID'   = $_.ProcessId;
            'User'        = if($processUser.User) { 
                "$($processUser.Domain)\$($processUser.User)" } else { "N/A" }
        }
    } | Format-Table -AutoSize
}









