<#
.SYNOPSIS
Displays a basic summary of local established connections.  

.DESCRIPTION
Collects all local connections in the "Established" state,
then displays the Creation Time, Local Address, Local Port, Remote Address,
Remote Port, and State in a table format. 

Works on Powershell v4 or greater. 
#>
function Get-EstablishedConnections {
    Get-NetTCPConnection | 
    Where-Object State -eq "Established" | 
    select-object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | 
    Sort-Object CreationTime -descending | 
    Format-Table -AutoSize
}


# For PowerShell 4+
# No process/user, everything
function Get-AllConnections {
    Get-NetTCPConnection | 
    select-object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | 
    Sort-Object CreationTime -descending | 
    Format-Table -AutoSize
}


# For PowerShell 4+ 
# With process/user info 
function Get-EstablishedConnectionsEnriched{
    $connections = Get-NetTCPConnection | Where-Object State -eq "Established" 
    $connectionInfo = $connections | ForEach-Object {
        $process = Get-Process -IncludeUserName -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            NetCreateTime = $_.CreationTime
            ProcessID     = $_.OwningProcess
            ProcessName   = $Process.Name
            Username      = $Process.UserName
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
        }
    }
    $connectionInfo | sort-object NetCreateTime -descending | Format-Table -AutoSize
}


# For PowerShell 4+ 
# With process/user info 
function Get-ConnectionsEnriched{
    $connections = Get-NetTCPConnection
    $connectionInfo = $connections | ForEach-Object {
        $process = Get-Process -IncludeUserName -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            NetCreateTime = $_.CreationTime
            ProcessID     = $_.OwningProcess
            ProcessName   = $Process.Name
            Username      = $Process.UserName
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
        }
    }
    $connectionInfo | sort-object NetCreateTime -descending | Format-Table -AutoSize
}


# For PowerShell < v4
function Get-ConnectionsEnrichedV3{
    $netstatOutput = netstat -ano | 
    Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+:\d+\s+\d+\.\d+\.\d+\.\d+:\d+\s+\w+\s+\d+' }

    $connectionInfo = $netstatOutput | ForEach-Object {
        if ($_ -match '\d+\.\d+\.\d+\.\d+:\d+\s+(\d+\.\d+\.\d+\.\d+):\d+\s+(\w+)\s+(\d+)') {
            $localAddress = $matches[0].Split()[0]
            $foreignAddress = $matches[1]
            $state = $matches[2]
            $pid1 = $matches[3]

            $process = Get-Process -Id $pid1 -ErrorAction SilentlyContinue

            $owner = (Get-WmiObject -Class Win32_Process -Filter "ProcessId=$pid1").GetOwner()

            [PSCustomObject]@{
                ProcessID   = $pid1
                ProcessName = if ($process) { $process.Name } else { "N/A" }
                Username    = if ($owner) { "$($owner.Domain)\$($owner.User)" } else { "N/A" }
                LocalAddress  = $localAddress
                ForeignAddress = $foreignAddress
                State         = $state
            }
        }
    }
    $connectionInfo 
}