<#
.SYNOPSIS
Checks scripts/wec_forwarder.ps1 against a stand-in for Get-WinEvent and a running Watchpost server.

.DESCRIPTION
Not part of ./run_tests.sh, which is Python only. tests/test_wec_forwarder.py runs this when PowerShell is
installed: it starts a Watchpost test server, passes its URL here, and then checks what was stored.

    $env:WATCHPOST_TOKEN = 'wp_...'
    pwsh tests/wec_forwarder_check.ps1 -Url http://127.0.0.1:8080

It runs anywhere PowerShell 7 does. It does not need Windows, and for that reason it proves the script's logic
and nothing about a real ForwardedEvents log. All event data here is synthetic.
#>
param([Parameter(Mandatory)] [string] $Url)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
# Dot-sourcing the forwarder also sets its parameters here, $Url among them, to their defaults. Keep ours first.
$Watchpost = $Url
. (Join-Path $PSScriptRoot '..' 'scripts' 'wec_forwarder.ps1')
$Url = $Watchpost

$script:Failures = 0
function Assert-That {
    param([bool] $Condition, [string] $What)
    if ($Condition) { Write-Host "  ok   $What" } else { Write-Host "  FAIL $What"; $script:Failures++ }
}

function New-EventXml {
    # A synthetic event the way Get-WinEvent's ToXml() writes one.
    param([long] $RecordId, [int] $EventId = 4625, [string] $When = '2026-09-14T15:10:00.1234567Z',
          [string] $Address = '198.51.100.60', [string] $Extra = '', [switch] $Rendered)
    $rendering = ''
    if ($Rendered) { $rendering = "<RenderingInfo Culture='en-US'><Message>[SYNTHETIC] An account failed to log on.`r`n`r`nSubject:</Message></RenderingInfo>" }
    return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" +
        "<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>" +
        "<EventID>$EventId</EventID><Version>0</Version><Level>0</Level><TimeCreated SystemTime='$When'/>" +
        "<EventRecordID>$RecordId</EventRecordID><Channel>Security</Channel><Computer>dc01.corp.example</Computer></System>" +
        "<EventData><Data Name='TargetUserName'>jsmith</Data><Data Name='IpAddress'>$Address</Data>" +
        "<Data Name='LogonType'>3</Data>$Extra</EventData>$rendering</Event>"
}

# --- the stand-in for the ForwardedEvents log -----------------------------------------
$script:Log = New-Object System.Collections.ArrayList
$script:Queries = 0
function Add-FakeEvent {
    param([long] $RecordId, [string] $Xml)
    $item = [pscustomobject]@{ RecordId = $RecordId; Xml = $Xml }
    Add-Member -InputObject $item -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    [void] $script:Log.Add($item)
}
function Get-WinEvent {
    param([string] $LogName, [string] $FilterXPath, [switch] $Oldest, [int] $MaxEvents = 1, $ErrorAction)
    $script:Queries++
    if ($FilterXPath -match 'EventRecordID > (\d+)') {
        $after = [long] $Matches[1]
        $found = @($script:Log | Where-Object { $_.RecordId -gt $after } | Select-Object -First $MaxEvents)
    } else {
        $found = @($script:Log | Select-Object -Last 1)
    }
    if (-not $found.Count) { throw 'No events were found that match the specified selection criteria.' }
    return $found
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("wec-check-" + [guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Path $work)
$state = Join-Path $work 'state.json'
$token = $env:WATCHPOST_TOKEN
$run = { param($Count = 500, $To = $Url, $With = $token, $Retries = -1, $StateFile = $state, $As = 'wec', [switch] $Start)
    Invoke-Forwarder -BaseUrl $To -Token $With -Log 'ForwardedEvents' -State $StateFile -SourceName $As -Count $Count -MaxRetries $Retries -Start:$Start }
$position = { (Get-Content -LiteralPath $state -Raw | ConvertFrom-Json).last_record_id }

Write-Host '== one event becomes one record'
$record = ConvertTo-WatchpostRecord (New-EventXml 1001 -Rendered) 'wec' 'WEC01'
Assert-That ($record['EventID'] -eq 4625 -and $record['EventID'] -is [int]) 'EventID is a number'
Assert-That ($record['TimeCreated'] -eq '2026-09-14T15:10:00.123456Z') 'the time is cut to microseconds'
Assert-That ($record['Computer'] -eq 'dc01.corp.example' -and $record['TargetUserName'] -eq 'jsmith' -and $record['IpAddress'] -eq '198.51.100.60') 'the fields Watchpost reads are there'
Assert-That ($record['source'] -eq 'wec' -and $record['EventChannel'] -eq 'Security' -and $record['EventRecordID'] -eq '1001' -and $record['wec_collector'] -eq 'WEC01') 'source, channel, record number and collector'
Assert-That ($record['message'] -eq '[SYNTHETIC] An account failed to log on.') 'the message is the first rendered line'
Assert-That ((ConvertTo-WatchpostRecord (New-EventXml 1) 'wec' 'W')['message'] -eq 'Windows event 4625 (Microsoft-Windows-Security-Auditing)') 'without rendering, the message names the event'

$extra = "<Data Name='level'>Verbose</Data><Data Name='time'>yesterday</Data><Data Name='ip'>n/a</Data><Data>unnamed</Data><Data Name='a b/c'>x</Data><Data Name='Big'>$('n' * 5000)</Data>"
foreach ($address in '-', 'LOCAL', 'ws17.corp.example', '5') {
    $moved = ConvertTo-WatchpostRecord (New-EventXml 2 -Address $address -Extra $extra) 'wec' 'W'
    Assert-That (-not $moved.Contains('IpAddress') -and $moved['win_IpAddress'] -eq $address) "an address of '$address' is moved aside"
}
Assert-That ($moved['win_level'] -eq 'Verbose' -and $moved['win_time'] -eq 'yesterday' -and $moved['win_ip'] -eq 'n/a') 'names Watchpost reserves are renamed'
Assert-That ($moved['Data7'] -eq 'unnamed' -and $moved['a_b_c'] -eq 'x' -and $moved['Big'].Length -eq 512) 'unnamed, odd and long values'
$cleared = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><TimeCreated SystemTime='2026-09-14T15:12:00.5Z'/><Computer>dc01</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData></Event>"
Assert-That ((ConvertTo-WatchpostRecord $cleared 'wec' 'W')['SubjectUserName'] -eq 'admin') 'UserData fields are read'
Assert-That ($null -eq (ConvertTo-WatchpostRecord '<NotAnEvent/>' 'wec' 'W')) 'something that is not an event gives nothing'
Assert-That ((ConvertTo-WatchpostRecord (New-EventXml 3 -Address '2001:db8::5') 'wec' 'W')['IpAddress'] -eq '2001:db8::5') 'an IPv6 address is kept'

Write-Host '== the first run starts at the newest event'
1..3 | ForEach-Object { Add-FakeEvent $_ (New-EventXml $_) }
Assert-That ((& $run) -eq 0 -and (& $position) -eq 3) 'nothing sent, position at record 3'

Write-Host '== new events are sent and the position moves'
Add-FakeEvent 4 (New-EventXml 4 -When '2026-09-14T15:20:00.0000000Z' -Rendered)
Add-FakeEvent 5 (New-EventXml 5 -EventId 4624 -When '2026-09-14T15:21:00.0000000Z')
Assert-That ((& $run) -eq 2 -and (& $position) -eq 5) 'two events sent, position at record 5'
Assert-That ((& $run) -eq 0) 'a second pass sends nothing'

Write-Host '== a long backlog goes out in batches'
6..10 | ForEach-Object { Add-FakeEvent $_ (New-EventXml $_ -EventId 4624 -When "2026-09-14T15:3$($_ - 6):00.0000000Z") }
$before = $script:Queries
Assert-That ((& $run 2) -eq 5 -and (& $position) -eq 10) 'five events sent two at a time'
Assert-That (($script:Queries - $before) -eq 4) 'three batches and one empty look'

Write-Host '== a batch Watchpost refuses is skipped; an unreadable event costs only itself'
Add-FakeEvent 11 (New-EventXml 11 -When '2999-01-01T00:00:00.0000000Z')
Assert-That ((& $run) -eq 0 -and (& $position) -eq 11) 'the refused batch is skipped and the position moves past it'
Add-FakeEvent 12 '<Event><broken'
Add-FakeEvent 13 (New-EventXml 13 -EventId 4624 -When '2026-09-14T15:40:00.0000000Z')
Assert-That ((& $run) -eq 1 -and (& $position) -eq 13) 'one of two events sent, position at record 13'

Write-Host '== nothing is lost while Watchpost cannot be reached or refuses the token'
Add-FakeEvent 14 (New-EventXml 14 -EventId 4624 -When '2026-09-14T15:41:00.0000000Z')
$failed = $false
try { [void] (& $run 500 'http://127.0.0.1:9' $token 1) } catch { $failed = "$($_.Exception.Message)" -like '*giving up*' }
Assert-That ($failed -and (& $position) -eq 13) 'unreachable: gives up, position unchanged'
$failed = $false
try { [void] (& $run 500 $Url 'wp_not-a-real-token-0123456789abcdef' 0) } catch { $failed = "$($_.Exception.Message)" -like '*HTTP 401*' }
Assert-That ($failed -and (& $position) -eq 13) 'wrong token: gives up with HTTP 401, position unchanged'
Assert-That ((& $run) -eq 1 -and (& $position) -eq 14) 'the same event goes through once Watchpost answers'

Write-Host '== -FromStart sends what the log already holds'
$replay = Join-Path $work 'replay.json'
Assert-That ((& $run 500 $Url $token -1 $replay 'wec-replay' -Start) -eq 13) 'thirteen readable events sent in one batch'

Write-Host '== the URL and the token are checked before anything is sent'
foreach ($bad in 'http://siem.example.internal', 'ftp://127.0.0.1/x', 'not a url') {
    $refused = $false
    try { [void] (Test-WatchpostUrl $bad) } catch { $refused = $true }
    Assert-That $refused "refuses $bad"
}
Assert-That ((Test-WatchpostUrl 'https://siem.example.internal/') -eq 'https://siem.example.internal') 'accepts https'
Assert-That ((Test-WatchpostUrl 'http://127.0.0.1:8080') -eq 'http://127.0.0.1:8080') 'accepts http to this machine'
$env:WATCHPOST_TOKEN = ''
$refused = $false
try { [void] (Get-WatchpostToken (Join-Path $work 'missing.txt')) } catch { $refused = $true }
Assert-That $refused 'no token: refuses to start'
Set-Content -LiteralPath (Join-Path $work 'token.txt') -Value "  $token  "
Assert-That ((Get-WatchpostToken (Join-Path $work 'token.txt')) -eq $token) 'the token is read from a file'
$env:WATCHPOST_TOKEN = $token

Write-Host '== the script itself, run to the end'
$child = Join-Path $work 'child.ps1'
$forwarder = Join-Path $PSScriptRoot '..' 'scripts' 'wec_forwarder.ps1'
@"
function Get-WinEvent {
    param([string] `$LogName, [string] `$FilterXPath, [switch] `$Oldest, [int] `$MaxEvents = 1, `$ErrorAction)
    if (`$FilterXPath -match 'EventRecordID > (\d+)' -and [long] `$Matches[1] -lt 2) {
        `$item = [pscustomobject]@{ RecordId = [long] 2 }
        Add-Member -InputObject `$item -MemberType ScriptMethod -Name ToXml -Value { "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><TimeCreated SystemTime='2026-09-14T15:50:00.0000000Z'/><EventRecordID>2</EventRecordID><Channel>Security</Channel><Computer>dc01.corp.example</Computer></System><EventData><Data Name='TargetUserName'>jsmith</Data></EventData></Event>" }
        return @(`$item)
    }
    throw 'No events were found that match the specified selection criteria.'
}
& '$forwarder' -Url '$Url' -Once -FromStart -Source 'wec-main' -StatePath '$(Join-Path $work 'main.json')'
"@ | Set-Content -LiteralPath $child
$output = (& pwsh -NoLogo -NoProfile -File $child 2>&1 | Out-String)
Assert-That ($LASTEXITCODE -eq 0) "exit code 0 (was $LASTEXITCODE)"
Assert-That ($output -match 'sent 1 event\(s\), up to record 2') 'it reports what it sent'
Assert-That (-not $output.Contains($token)) 'the token is not in its output'
Assert-That (-not $output.Contains('jsmith')) 'event contents are not in its output'
$output = (& pwsh -NoLogo -NoProfile -File $forwarder -Url 'http://siem.example.internal' -Once 2>&1 | Out-String)
Assert-That ($LASTEXITCODE -eq 2 -and $output -match 'fatal: refusing to send the token over plain HTTP') 'plain HTTP to another host: exit code 2'

Remove-Item -LiteralPath $work -Recurse -Force
if ($script:Failures) { Write-Host "WEC FORWARDER CHECK FAILED ($($script:Failures))"; exit 1 }
Write-Host 'WEC FORWARDER CHECK OK'
