<#
.SYNOPSIS
Watchpost forwarder for a Windows Event Collector: sends the collector's forwarded events to Watchpost.

.DESCRIPTION
A Windows domain usually gathers event logs with the Windows Event Collector service: the hosts push their
events to one collector server, with nothing installed on them, and the events land in that server's
ForwardedEvents log. This script runs on the collector server. It reads that log and posts each event to
Watchpost's POST /api/ingest with an ingest token, in the same record shape as scripts/wef_collector.py.

    $env:WATCHPOST_TOKEN = 'wp_...'      # an ingest-only token created by an admin
    .\wec_forwarder.ps1 -Url https://siem.example.internal

Run it at startup as a scheduled task (see docs/LIVE_INGEST.md). It needs Windows PowerShell 5.1 or newer and
nothing else.

EXPERIMENTAL. The logic is tested with PowerShell 7 on Linux against a stand-in for Get-WinEvent and a real
Watchpost server. It has not been run on Windows, against a real ForwardedEvents log. Expect to correct it.

How it works:
- It remembers the record number of the last event Watchpost accepted, in the state file, and asks the log
  for what came after. A restart resumes there. On its first run it starts at the newest event, unless
  -FromStart is given.
- A batch is sent in one request. Network errors and 5xx answers are retried with a growing pause, and the
  position does not move until Watchpost has accepted the batch. A batch Watchpost refuses as invalid (400,
  413, 415, 422) is logged and skipped, so one bad event cannot block the log forever.
- The token is read from $env:WATCHPOST_TOKEN or from -TokenPath, never from the command line, and is never
  written to the output. Event contents are never written to the output.
- Plain HTTP is refused unless the URL points at this machine.

.PARAMETER Url
Watchpost base URL, for example https://siem.example.internal

.PARAMETER LogName
The log to read. ForwardedEvents is where the Windows Event Collector puts what it receives.

.PARAMETER StatePath
Where the position is kept. Default: %ProgramData%\Watchpost\wec-forwarder.json

.PARAMETER TokenPath
A file holding the ingest token, used when $env:WATCHPOST_TOKEN is not set. Restrict who can read it.
Default: %ProgramData%\Watchpost\token.txt

.PARAMETER Source
Source name for the events in Watchpost.

.PARAMETER BatchSize
Events per request, at most.

.PARAMETER IntervalSeconds
Pause between looks at the log when there is nothing new.

.PARAMETER Once
Send what is waiting and exit.

.PARAMETER FromStart
On the first run, send the events the log already holds instead of starting at the newest.
#>
[CmdletBinding()]
param(
    [string] $Url,
    [string] $LogName = 'ForwardedEvents',
    [string] $StatePath = '',
    [string] $TokenPath = '',
    [string] $Source = 'wec',
    [ValidateRange(1, 5000)] [int] $BatchSize = 500,
    [ValidateRange(1, 3600)] [int] $IntervalSeconds = 15,
    [switch] $Once,
    [switch] $FromStart
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$SkipStatuses = 400, 413, 415, 422   # Watchpost refused the batch itself; resending cannot help
$MaxDataFields = 64
$MaxValue = 512
$MaxBackoffSeconds = 60

# Field names Watchpost reads from a record (normalize.FIELD_ALIASES). Event data under one of these names is
# renamed, so a provider's own "level" or "time" field cannot make Watchpost refuse the event. Keep this list
# the same as RESERVED_FIELDS in scripts/wef_collector.py; tests/test_wec_forwarder.py compares the two.
$ReservedFields = @(
    'ts', 'timestamp', '@timestamp', 'time', 'TimeCreated', 'event_time', 'source', 'log_source', 'Channel', 'host',
    'hostname', 'Computer', 'device', 'event_type', 'type', 'action', 'category', 'outcome', 'result', 'status',
    'severity', 'level', 'user', 'username', 'user_name', 'TargetUserName', 'account', 'src_ip', 'source_ip',
    'client_ip', 'ip', 'IpAddress', 'remote_addr', 'dest_ip', 'destination_ip', 'server_ip', 'dst_ip', 'dest_port',
    'destination_port', 'dst_port', 'dport', 'bytes', 'bytes_out', 'bytes_sent', 'sent_bytes', 'out_bytes',
    'message', 'msg', 'description', 'EventID', 'event_id', 'raw', 'synthetic'
)
$WindowsFields = @('TargetUserName', 'IpAddress')   # event data Watchpost is meant to read

function Write-Log {
    # Write-Host, not Write-Output: a function's output is its return value, and log lines must not join it.
    param([string] $Message)
    Write-Host ("{0} wec: {1}" -f (Get-Date -Format 's'), $Message)
}

function Test-WatchpostUrl {
    # Refuses anything but https, except http to this machine.
    param([string] $Value)
    $parsed = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref] $parsed)) { throw "-Url must be an http(s) URL" }
    if ($parsed.Scheme -eq 'https') { return $Value.TrimEnd('/') }
    if ($parsed.Scheme -eq 'http' -and ($parsed.IsLoopback)) { return $Value.TrimEnd('/') }
    throw "refusing to send the token over plain HTTP to $($parsed.Host); use https://"
}

function Get-WatchpostToken {
    param([string] $Path)
    $token = $env:WATCHPOST_TOKEN
    if (-not $token -and $Path -and (Test-Path -LiteralPath $Path)) { $token = Get-Content -LiteralPath $Path -Raw }
    if ($token) { $token = $token.Trim() }
    if (-not $token -or -not $token.StartsWith('wp_')) {
        throw 'no ingest token: set $env:WATCHPOST_TOKEN or put it in the -TokenPath file (tokens start with wp_)'
    }
    return $token
}

function ConvertTo-FieldName {
    param([string] $Name)
    $clean = [regex]::Replace($Name, '[^A-Za-z0-9_.@-]', '_')
    if ($clean.Length -gt 64) { $clean = $clean.Substring(0, 64) }
    if (-not $clean) { $clean = 'Data' }
    if (($ReservedFields -ccontains $clean) -and -not ($WindowsFields -ccontains $clean)) { return "win_$clean" }
    return $clean
}

function Limit-Text {
    param([string] $Text, [int] $Length = $MaxValue)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -gt $Length) { return $Text.Substring(0, $Length) }
    return $Text
}

function ConvertTo-WatchpostRecord {
    # One Windows event, as the XML Get-WinEvent gives for it, as a flat record for /api/ingest.
    # Returns $null for something that is not an event.
    param([string] $EventXml, [string] $SourceName, [string] $Collector)
    $document = New-Object System.Xml.XmlDocument
    $document.XmlResolver = $null          # no external entities
    $document.LoadXml($EventXml)
    $root = $document.DocumentElement
    if ($null -eq $root -or $root.LocalName -ne 'Event') { return $null }
    $system = $root.ChildNodes | Where-Object { $_.LocalName -eq 'System' } | Select-Object -First 1
    if ($null -eq $system) { return $null }
    $sys = @{}
    foreach ($node in $system.ChildNodes) { if ($node.NodeType -eq 'Element') { $sys[$node.LocalName] = $node } }
    if (-not $sys.ContainsKey('EventID')) { return $null }

    $record = [ordered]@{}
    $named = New-Object System.Collections.ArrayList
    $eventData = $root.ChildNodes | Where-Object { $_.LocalName -eq 'EventData' } | Select-Object -First 1
    if ($null -ne $eventData) {
        $index = 0
        foreach ($item in $eventData.ChildNodes) {
            if ($item.NodeType -ne 'Element') { continue }
            $index++
            $name = $item.GetAttribute('Name')
            if (-not $name) { $name = "Data$index" }
            [void] $named.Add(@($name, $item.InnerText))
        }
    }
    $userData = $root.ChildNodes | Where-Object { $_.LocalName -eq 'UserData' } | Select-Object -First 1
    if ($null -ne $userData -and $null -ne $userData.FirstChild) {
        foreach ($item in $userData.FirstChild.ChildNodes) {
            if ($item.NodeType -eq 'Element') { [void] $named.Add(@($item.LocalName, $item.InnerText)) }
        }
    }
    $taken = 0
    foreach ($pair in $named) {
        if ($taken -ge $MaxDataFields) { break }
        $taken++
        $record[(ConvertTo-FieldName $pair[0])] = Limit-Text $pair[1]
    }

    if ($record.Contains('IpAddress')) {
        # "-", "LOCAL" or a host name would make Watchpost refuse the whole event.
        $address = "$($record['IpAddress'])".Trim()
        $parsedAddress = $null
        $record.Remove('IpAddress')
        if ($address -and [System.Net.IPAddress]::TryParse($address, [ref] $parsedAddress) -and $address -match '[.:]') {
            $record['IpAddress'] = $parsedAddress.ToString()
        } elseif ($address) {
            $record['win_IpAddress'] = $address
        }
    }

    $value = { param($name) if ($sys.ContainsKey($name)) { Limit-Text $sys[$name].InnerText.Trim() } else { '' } }
    $eventId = (& $value 'EventID')
    $provider = ''
    if ($sys.ContainsKey('Provider')) { $provider = Limit-Text $sys['Provider'].GetAttribute('Name') }
    $when = ''
    if ($sys.ContainsKey('TimeCreated')) { $when = $sys['TimeCreated'].GetAttribute('SystemTime') }
    $when = [regex]::Replace($when, '(\.\d{6})\d+', '$1')      # Watchpost reads microseconds, Windows writes more
    $message = ''
    $rendering = $root.ChildNodes | Where-Object { $_.LocalName -eq 'RenderingInfo' } | Select-Object -First 1
    if ($null -ne $rendering) {
        $text = $rendering.ChildNodes | Where-Object { $_.LocalName -eq 'Message' } | Select-Object -First 1
        if ($null -ne $text) { $message = (($text.InnerText -split "`r?`n")[0]).Trim() }
    }
    if (-not $message) { $message = "Windows event $(Limit-Text $eventId 16) ($(Limit-Text $provider 100))" }

    $record['source'] = $SourceName
    $record['TimeCreated'] = $when
    $record['Computer'] = (& $value 'Computer')
    if ($eventId -match '^\d+$') { $record['EventID'] = [int] $eventId } else { $record['EventID'] = Limit-Text $eventId 16 }
    $record['EventChannel'] = (& $value 'Channel')
    $record['Provider'] = $provider
    $record['EventRecordID'] = (& $value 'EventRecordID')
    $record['Level'] = (& $value 'Level')
    $record['wec_collector'] = $Collector
    $record['message'] = Limit-Text $message 300
    return $record
}

function Read-ForwarderState {
    param([string] $Path)
    if (Test-Path -LiteralPath $Path) {
        try {
            $state = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            if ($null -ne $state -and $null -ne $state.last_record_id) { return [long] $state.last_record_id }
        } catch {
            Write-Log "ignoring an unreadable state file"
        }
    }
    return $null
}

function Save-ForwarderState {
    param([string] $Path, [long] $RecordId, [string] $Log)
    $folder = Split-Path -Parent $Path
    if ($folder -and -not (Test-Path -LiteralPath $folder)) { [void] (New-Item -ItemType Directory -Path $folder -Force) }
    $json = ConvertTo-Json -InputObject ([ordered]@{ log = $Log; last_record_id = $RecordId }) -Compress
    $temporary = "$Path.tmp"
    [System.IO.File]::WriteAllText($temporary, $json)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-NewEvents {
    # The next events after a record number, oldest first. An empty log is not an error.
    param([string] $Log, [long] $After, [int] $Count)
    try {
        return @(Get-WinEvent -LogName $Log -FilterXPath "*[System[EventRecordID > $After]]" -Oldest -MaxEvents $Count -ErrorAction Stop)
    } catch {
        if ("$($_.FullyQualifiedErrorId)" -like 'NoMatchingEventsFound*' -or "$($_.Exception.Message)" -like '*No events were found*') { return @() }
        throw
    }
}

function Get-NewestRecordId {
    param([string] $Log)
    try {
        $newest = @(Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction Stop)
        if ($newest.Count) { return [long] $newest[0].RecordId }
    } catch {
        if (-not ("$($_.FullyQualifiedErrorId)" -like 'NoMatchingEventsFound*' -or "$($_.Exception.Message)" -like '*No events were found*')) { throw }
    }
    return [long] 0
}

function Send-WatchpostBatch {
    # Returns the HTTP status Watchpost answered with, or 0 when it could not be reached.
    param([string] $BaseUrl, [string] $Token, [string] $SourceName, [object[]] $Records)
    $body = ConvertTo-Json -InputObject ([ordered]@{ source = $SourceName; events = @($Records) }) -Depth 4 -Compress
    try {
        [void] (Invoke-RestMethod -Uri "$BaseUrl/api/ingest" -Method Post -ContentType 'application/json' `
                -Headers @{ Authorization = "Bearer $Token" } -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 30)
        return 201
    } catch {
        $response = $null
        if ($_.Exception.PSObject.Properties['Response']) { $response = $_.Exception.Response }
        if ($null -ne $response) { return [int] $response.StatusCode }
        Write-Log "the request did not get an answer: $($_.Exception.GetType().Name): $($_.Exception.Message)"
        return 0
    }
}

function Invoke-Forwarder {
    # One pass: send everything that is waiting. Returns the number of events Watchpost accepted.
    # -MaxRetries limits the attempts per batch; without it a batch is retried until it goes through.
    param([string] $BaseUrl, [string] $Token, [string] $Log, [string] $State, [string] $SourceName, [int] $Count,
          [switch] $Start, [int] $MaxRetries = -1)
    $last = Read-ForwarderState $State
    if ($null -eq $last) {
        if ($Start) { $last = [long] 0 } else { $last = Get-NewestRecordId $Log }
        Save-ForwarderState $State $last $Log
        Write-Log "first run: starting after record $last of $Log"
    }
    $sent = 0
    while ($true) {
        $events = @(Get-NewEvents $Log $last $Count)
        if (-not $events.Count) { break }
        $records = New-Object System.Collections.ArrayList
        $unreadable = 0
        foreach ($item in $events) {
            try {
                $record = ConvertTo-WatchpostRecord $item.ToXml() $SourceName $env:COMPUTERNAME
                if ($null -ne $record) { [void] $records.Add($record) }
            } catch {
                $unreadable++
            }
        }
        $newest = [long] $events[$events.Count - 1].RecordId
        $delay = 1
        $attempt = 0
        $accepted = $false
        while ($records.Count) {
            $status = Send-WatchpostBatch $BaseUrl $Token $SourceName $records.ToArray()
            if ($status -eq 201 -or $status -eq 207) { $sent += $records.Count; $accepted = $true; break }
            if ($SkipStatuses -contains $status) {
                Write-Log "Watchpost refused a batch of $($records.Count) event(s) ($status); skipping it"
                break
            }
            $attempt++
            if ($MaxRetries -ge 0 -and $attempt -gt $MaxRetries) {
                throw "giving up after $MaxRetries retries (HTTP $status); the position was not moved"
            }
            $hint = ''
            if ($status -eq 401 -or $status -eq 403) { $hint = ' (check the ingest token; it may be revoked)' }
            if ($status -eq 0) { $reason = 'Watchpost could not be reached' } else { $reason = "HTTP $status$hint" }
            Write-Log "${reason}; retrying in $delay s"
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, $MaxBackoffSeconds)
        }
        if ($unreadable) { Write-Log "$unreadable event(s) could not be read and were left out" }
        $last = $newest
        Save-ForwarderState $State $last $Log
        if ($accepted) { Write-Log "sent $($records.Count) event(s), up to record $last" }
    }
    return $sent
}

# Dot-sourcing the script (. .\wec_forwarder.ps1) loads the functions without running anything.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        if (-not $Url) { throw '-Url is required, for example -Url https://siem.example.internal' }
        $folder = $env:ProgramData
        if (-not $folder) { $folder = [System.IO.Path]::GetTempPath() }
        if (-not $StatePath) { $StatePath = Join-Path (Join-Path $folder 'Watchpost') 'wec-forwarder.json' }
        if (-not $TokenPath) { $TokenPath = Join-Path (Join-Path $folder 'Watchpost') 'token.txt' }
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $base = Test-WatchpostUrl $Url
        $token = Get-WatchpostToken $TokenPath
        Write-Log "forwarding $LogName to Watchpost"
        if ($Once) {
            [void] (Invoke-Forwarder -BaseUrl $base -Token $token -Log $LogName -State $StatePath -SourceName $Source -Count $BatchSize -Start:$FromStart -MaxRetries 5)
            exit 0
        }
        while ($true) {
            [void] (Invoke-Forwarder -BaseUrl $base -Token $token -Log $LogName -State $StatePath -SourceName $Source -Count $BatchSize -Start:$FromStart)
            Start-Sleep -Seconds $IntervalSeconds
        }
    } catch {
        Write-Log "fatal: $($_.Exception.Message)"
        exit 2
    }
}
