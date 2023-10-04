# Add date/time options 
# Add maxevents options
# Convert everything to the hash table option

function Get-UserSessions{
    $results = @()
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -ErrorAction SilentlyContinue | ForEach-Object {
        $xmlData = [xml]$_.ToXml()
        
        $accountName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $accountDomain = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        $logonID = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetLogonId' }).'#text'
        $logonType = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        $processName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessName' }).'#text'
        $workstationName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
        $sourceAddress = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $sourcePort = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'IpPort' }).'#text'
        $elevatedTokenRaw = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'ElevatedToken' }).'#text'
        
        # Common accounts to ignore
        $ignoreAccounts = @('SYSTEM', 'DWM-1', 'UMFD-0', 'UMFD-1', 'ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE')

        # Skip this iteration if the account name is in the ignore list
        if ($ignoreAccounts -contains $accountName) {
            return
        }

        $elevatedToken = switch ($elevatedTokenRaw) {
            "%%1843" { "No" }
            "%%1842" { "Yes" } 
            default { $elevatedTokenRaw } 
        }

        $results += [PSCustomObject]@{
            "Time Created (UTC)"     = $_.TimeCreated.ToUniversalTime()
            "Account Name"           = $accountName
            "Domain"                 = $accountDomain
            "Logon ID"               = '0x{0:X}' -f [int64]$logonID
            "Logon Type"             = $logonType
            "Process Name"           = $processName
            "Workstation Name"       = $workstationName
            "Source Network Address" = $sourceAddress
            "Source Port"            = $sourcePort
            "Elevated Token"         = $elevatedToken
        } 
    }
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4634]]" | ForEach-Object {
        $xmlData = [xml]$_.ToXml()

        $accountName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $domain = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        $logonID = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetLogonId' }).'#text'
        $logonType = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'

        $results += [PSCustomObject]@{
            'Time Created (UTC)'     = $_.TimeCreated.ToUniversalTime()
            'Account Name'           = $accountName
            'Domain'                 = $domain
            'Logon ID'               = $logonID
            'Logon Type'             = $logonType
            "Process Name"           = "N/A"
            "Workstation Name"       = "N/A"
            "Source Network Address" = "N/A"
            "Source Port"            = "N/A"
            "Elevated Token"         = "N/A"
        }
    }
    $results | Sort-Object -Descending 'Time Created (UTC)'
}

# Expirimental 
# This one is magnituted faster, but the hardcoded values results in possible incorrect column mapping
function Get-LogonEventsEXPIREMENTAL{
    $events = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -ErrorAction SilentlyContinue

    $ignoreAccounts = @('SYSTEM', 'DWM-1', 'UMFD-0', 'UMFD-1', 'ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE')

    $events | ForEach-Object {
        $accountName = $_.Properties[5].Value

        # Skip this iteration if the account name is in the ignore list
        if ($ignoreAccounts -contains $accountName) {
            return
        }

        $elevatedTokenRaw = $_.Properties[-1].Value
        $elevatedToken = switch ($elevatedTokenRaw) {
            "%%1843" { "No" }
            "%%1842" { "Yes" } 
            default { $elevatedTokenRaw } 
        }

        [PSCustomObject]@{
            "Time Created (UTC)" = $_.TimeCreated.ToUniversalTime()
            "Account Name" = $accountName
            "Account Domain" = $_.Properties[6].Value
            "Logon ID" = '0x{0:X}' -f [int64]$_.Properties[7].Value
            "Logon Type" = $_.Properties[8].Value
            "Process Name" = $_.Properties[17].Value
            "Workstation Name" = $_.Properties[11].Value
            "Source Network Address" = $_.Properties[18].Value
            "Source Port" = $_.Properties[19].Value
            "Elevated Token" = $elevatedToken
        }
    } 
}

function Get-Services{
    $results = @()

    Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" -ErrorAction SilentlyContinue | ForEach-Object {
        $xmlData = [xml]$_.ToXml()

        # Extract properties using their names
        $serviceName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
        $serviceFilePath = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
        $accountName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'AccountName' }).'#text'

        if ($serviceFilePath -contains "MpKslDrv.sys"){
            return
        }

        $results += [PSCustomObject]@{
            'Time Created (UTC)' = $_.TimeCreated.ToUniversalTime()
            'Service Name'       = $serviceName
            'Account Name'       = $accountName
            'Service File Path'  = $serviceFilePath
        }
    }
    $results
}

function Get-SystemStartup{
    $results = @()
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4608]]" -ErrorAction SilentlyContinue | ForEach-Object {
        $results += [PSCustomObject]@{
            'Time Created (UTC)' = $_.TimeCreated.ToUniversalTime()
            'Message' = "System Startup"
        }
    }
    $results
}

function Get-SystemShutdown{
    $results = @()
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4609]]" -ErrorAction SilentlyContinue | ForEach-Object {
        $results += [PSCustomObject]@{
            'Time Created (UTC)' = $_.TimeCreated.ToUniversalTime()
            'Message' = "System Shutdown"
        }
    }
    $results
}

function Get-TermServSessions{
    $results = @()
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ID=21} | ForEach-Object {
        $xmlData = [xml]$_.ToXml()
        $user = $xmlData.Event.UserData.EventXML.User 
        $sessionID = $xmlData.Event.UserData.EventXML.SessionID 
        $sourceNetworkAddress = $xmlData.Event.UserData.EventXML.Address

        $results += [PSCustomObject]@{
            'Time Created (UTC)'    = $_.TimeCreated.ToUniversalTime()
            'User'                  = $user
            'Session ID'            = $sessionID
            'Source Network Address'= $sourceNetworkAddress
            'Message'               = "Logon by $user"
        }
    }
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ID=23} | ForEach-Object {
        $xmlData = [xml]$_.ToXml()
        $user = $xmlData.Event.UserData.EventXML.User 
        $sessionID = $xmlData.Event.UserData.EventXML.SessionID 

        $results += [PSCustomObject]@{
            'Time Created (UTC)'    = $_.TimeCreated.ToUniversalTime()
            'User'                  = $user
            'Session ID'            = $sessionID
            'Source Network Address'= "N/A"
            'Message'               = "Logoff by $user"
        }
    }
    $results | Sort-Object -descending 'Time Created (UTC)' 
}

function Get-FailedLogons{
    $results = @()
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]]" | ForEach-Object {
        $xmlData = [xml]$_.ToXml()
        $accountName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $accountDomain = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        $callerProcessName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessName' }).'#text'
        $workstationName = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
        $sourceNetworkAddress = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $sourcePort = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'IpPort' }).'#text'
        $logonType = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        $FailureReasonRaw = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'FailureReason' }).'#text'
        $StatusRaw = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'Status' }).'#text'
        $SubStatusRaw = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'SubStatus' }).'#text'

        $FailureReason = switch ($FailureReasonRaw) {
            "%%2305" { 'The specified user account has expired.' }
            "%%2309" { "The specified account's password has expired." }
            "%%2310" { 'Account currently disabled.' }
            "%%2311" { 'Account logon time restriction violation.' }
            "%%2312" { 'User not allowed to logon at this computer.' }
            "%%2313" { 'Unknown user name or bad password.' }
            "%%2304" { 'An Error occurred during Logon.' }
            default { $FailureReasonRaw } 
        }
        $Status = switch ($StatusRaw) {
            "0xC0000234" { "Account locked out" }
            "0xC0000193" { "Account expired" }
            "0xC0000133" { "Clocks out of sync" }
            "0xC0000224" { "Password change required" }
            "0xc000015b" { "User does not have logon right" }
            "0xc000006d" { "Logon failure" }
            "0xc000006e" { "Account restriction" }
            "0xc00002ee" { "An error occurred during logon" }
            "0xC0000071" { "Password expired" }
            "0xC0000072" { "Account disabled" }
            "0xC0000413" { "Authentication firewall prohibits logon" }
            default { $StatusRaw }
        }
        $SubStatus = switch ($SubStatusRaw) {
            "0xC0000234" { "Account locked out" }
            "0xC0000193" { "Account expired" }
            "0xC0000133" { "Clocks out of sync" }
            "0xC0000224" { "Password change required" }
            "0xc000015b" { "User does not have logon right" }
            "0xc000006d" { "Logon failure" }
            "0xc000006e" { "Account restriction" }
            "0xc00002ee" { "An error occurred during logon" }
            "0xC0000071" { "Password expired" }
            "0xC0000072" { "Account disabled" }
            "0xC0000413" { "Authentication firewall prohibits logon" }
            default { $SubStatusRaw }
        }
        $results += [PSCustomObject]@{
            'Time Created (UTC)'    = $_.TimeCreated.ToUniversalTime()
            'Account Name'          = $accountName
            'Account Domain'        = $accountDomain
            'Logon Type'            = $logonType
            'Caller Process Name'   = $callerProcessName
            'Workstation Name'      = $workstationName
            'Source Network Address'= $sourceNetworkAddress
            'Source Port'           = $sourcePort
            'FailureReason'         = $FailureReason
            'Status'                = $Status
            'SubStatus'             = $SubStatus
        }
    }
    $results
}

function Get-OutboundRDPSucc{
    $results = @()

    Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -FilterXPath "*[System[EventID=1024]]" | ForEach-Object {
        $xmlData = [xml]$_.ToXml()

        $value = ($xmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'Value' }).'#text'

        $results += [PSCustomObject]@{
            'Time Created (UTC)' = $_.TimeCreated.ToUniversalTime()
            'Destination Hostname' = "RDP Connection to $value"
        }
    }
    $results 
}

function Get-PowerShellEvents{
    # Define the regular expression pattern to extract the command
    $pattern = "(?s)(?<=HostApplication=)(.*?)(?=EngineVersion=)"

    # Get the PowerShell events with ID 400
    $events = Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; ID=400} 

    # Define a custom object array to store the results
    $commandLogs = @()

    # Loop through each event
    foreach ($event in $events) {
        # Convert the event to XML
        $eventXml = [xml]$event.ToXml()

        # Extract the third Data field from the event's EventData
        $dataField = $eventXml.Event.EventData.Data[2]

        if ($dataField -match $pattern) {
            $command = $Matches[0]

            # Add the extracted details to the results array
            $commandLogs += [PSCustomObject]@{
                TimeStamp = $event.TimeCreated.ToUniversalTime()
                Command   = $command
            }
        }
    }

    # Output the results
    $commandLogs 
}

function Get-GenericLogClearing{
    # Get events with ID 104 from the System event log with source "Eventlog"
    $events = Get-WinEvent -LogName 'System' -FilterXPath "*[(System[Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=104])]"

    # Define a custom object array to store the results
    $clearLogs = @()

    # Loop through each event
    foreach ($event in $events) {
        # Convert the event to XML
        $eventXml = [xml]$event.ToXml()

        # Extract relevant details from the XML
        $userName = $eventXml.Event.UserData.LogFileCleared.SubjectUserName
        $channel = $eventXml.Event.UserData.LogFileCleared.Channel

        # Add the extracted details to the results array
        $clearLogs += [PSCustomObject]@{
            TimeStamp = $event.TimeCreated.ToUniversalTime()
            UserName  = $userName
            Message   = "The $channel log was cleared by $userName."
        }
    }

    # Output the results
    $clearLogs 
}

function Get-SecurityLogClearing{
# Get events with ID 1102 from the Security event log
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -ErrorAction SilentlyContinue

# Define a custom object array to store the results
$clearLogs = @()

# Loop through each event
foreach ($event in $events) {
    # Convert the event to XML
    $eventXml = [xml]$event.ToXml()

    # Extract relevant details from the XML
    $accountName = $eventXml.Event.UserData.LogFileCleared.SubjectUserName 
    $logonID = $eventXml.Event.UserData.LogFileCleared.SubjectLogonId 

    # Add the extracted details to the results array
    $clearLogs += [PSCustomObject]@{
        TimeStamp   = $event.TimeCreated.ToUniversalTime()
        AccountName = $accountName
        LogonID     = $logonID
        Message     = "Security Event Log cleared by $accountName"
    }
}

# Output the results
$clearLogs
}

function Get-DefenderDetections{
# Get events with ID 1116 from the Windows Defender event log
$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116} -ErrorAction SilentlyContinue

# Define a custom object array to store the results
$detections = @()

# Loop through each event
foreach ($event in $events) {
    # Convert the event to XML
    $eventXml = [xml]$event.ToXml()

    # Extract relevant details from the XML
    $user = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'Detection User' }
    $threatName = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'Threat Name' }).'#text'
    $path = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'Path' }).'#text'

    # Add the extracted details to the results array
    $detections += [PSCustomObject]@{
        TimeStamp   = $event.TimeCreated.ToUniversalTime()
        User        = $user.'#text'
        Message     = "$threatName detected at $path"
    }
}

# Output the results
$detections | Format-Table -AutoSize
}

function Get-SysmonCheck{
    $sysmonLogName = 'Microsoft-Windows-Sysmon/Operational'

    try {
        $sysmonLog = Get-WinEvent -LogName $sysmonLogName -MaxEvents 1 -ErrorAction Stop
        if ($sysmonLog) {
            Write-Output "Sysmon event logs are available."
        }
    }
    catch {
        Write-Warning "Sysmon event logs are not available."
    }

}

function Get-SysmonProcessCreate{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [string]$startDate = "01/01/1980",
        [string]$endDate = ((Get-Date).AddDays(1)).ToString("MM/dd/yyyy"),
        [int]$maxEvents = 999999
    )
    
    # Check for MM/dd/yyyy formatting of the start date param
    try {
        $startDateTime = [datetime]::ParseExact($startDate, "MM/dd/yyyy", $null)
        $endDateTime = [datetime]::ParseExact($endDate, "MM/dd/yyyy", $null)
    } 
    catch {
        Write-Host "Invalid date format. Please use MM/dd/yyyy." -ForegroundColor Red
        return
    }

    # Query events 
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational";
        ID=1;
        StartTime=$startDateTime;
        EndTime=$endDateTime;
    } -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    # Checks if any events were returned 
    if ($events) {

        # Format events  
        $processCreations = @()
        foreach ($event in $events) {
            $eventXml = [xml]$event.ToXml()
            $user = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'User' }
            $ProcessID = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }
            $OriginalFileName = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'OriginalFileName' }
            $commandLine = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }
            $ParentCommandLine = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ParentCommandLine' }

            # Add the extracted details to the results array
            $processCreations += [PSCustomObject]@{
                TimeStamp          = $event.TimeCreated.ToUniversalTime()
                User               = $user.'#text'
                ProcessID          = $ProcessID.'#text'
                OriginalFileName   = $OriginalFileName.'#text'
                CommandLine        = $commandLine.'#text'
                ParentCommandLine  = $ParentCommandLine.'#text'
            }
        }
    } else {
        Write-Host "No events found." -ForegroundColor Yellow
    }
    $processCreations
}

function Get-SysmonNetCreate{
    # Get events with ID 3 (Network Connections) from Sysmon event log
    $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} -ErrorAction SilentlyContinue
    $networkConnections = @()

    foreach ($event in $events) {
        $eventXml = [xml]$event.ToXml()
        $user = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'User' }
        $destinationIp = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationIp' }
        $destinationHostname = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationHostname' }
        $destinationPort = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationPort' }
        $processId = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }
        $image = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }
        
        $networkConnections += [PSCustomObject]@{
            TimeStamp           = $event.TimeCreated.ToUniversalTime()
            User                = $user.'#text'
            DestinationIp       = $destinationIp.'#text'
            DestinationHostname = $destinationHostname.'#text'
            DestinationPort     = $destinationPort.'#text'
            ProcessId           = $processId.'#text'
            Image               = $image.'#text'
        }
    }

    $networkConnections

}

function Get-SysmonFileCreate{
    $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=11} -ErrorAction SilentlyContinue
    $fileCreations = @()

    foreach ($event in $events) {
        $eventXml = [xml]$event.ToXml()
        
        $user = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'User' }
        $targetFilename = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetFilename' }
        $processId = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }
        $image = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }
        
        $fileCreations += [PSCustomObject]@{
            TimeStamp       = $event.TimeCreated.ToUniversalTime()
            User            = $user.'#text'
            TargetFilename  = $targetFilename.'#text'
            ProcessId       = $processId.'#text'
            Image           = $image.'#text'
        }
    }

    $fileCreations | Format-Table -AutoSize

}