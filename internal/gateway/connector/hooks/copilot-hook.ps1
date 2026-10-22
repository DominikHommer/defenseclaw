# defenseclaw-managed-hook v7
# defenseclaw-copilot-closed-adapter v1
# Copilot CLI on Windows sends each hook event as UTF-8 JSON on stdin. The
# release hook launcher uses the GUI subsystem, so Start-Process cannot be
# trusted to inherit redirected stdin/stdout. This adapter preserves the bytes
# in memory, waits inside Copilot's 30-second hook budget, and answers
# tool-boundary integration errors with Copilot's native denial in closed mode.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'sessionStart', 'sessionEnd', 'userPromptSubmitted', 'userPromptTransformed',
        'preToolUse', 'postToolUse', 'permissionRequest', 'agentStop',
        'subagentStart', 'subagentStop', 'postToolUseFailure', 'errorOccurred',
        'preCompact', 'notification'
    )]
    [string]$Event
)

$ErrorActionPreference = 'Stop'
$hook = '{{.HookBinaryPS}}'
$timeoutMS = {{.CopilotHookTimeoutMS}}
$failClosed = '{{if .SecureClientDelivery}}false{{else}}{{if eq .FailMode "open"}}false{{else}}true{{end}}{{end}}' -eq 'true'
{{if not .SecureClientDelivery}}if ($env:DEFENSECLAW_STRICT_AVAILABILITY -in @('1', 'true', 'TRUE', 'yes', 'YES')) {
    $failClosed = $true
}
{{end}}
$process = $null
$started = $false
$stdinClosed = $false
$answerUnchecked = $false
$deadline = [System.Diagnostics.Stopwatch]::StartNew()

# Copilot reads a hook answer with JSON.parse: strict JSON grammar, exact
# (case-sensitive) keys, the last duplicate key wins, any nesting depth.
# ConvertFrom-Json differs on each point (it rejects keys that differ only by
# case and caps depth), so the denial check reads the child's answer here with
# Copilot's rules. Returns the top-level members of one JSON object (decoded
# strings; $null for any other value), $null for any other text, or 'budget'
# when the check cannot finish inside the hook budget.
function Read-CopilotAnswerMembers {
    param([string]$Text, [System.Diagnostics.Stopwatch]$Clock, [int]$BudgetMS)
    $t = $Text.Trim()
    while ($t.Length -gt 0 -and ($t[0] -eq [char]0xFEFF -or $t[$t.Length - 1] -eq [char]0xFEFF)) {
        $t = $t.Trim([char]0xFEFF).Trim()
    }
    $n = $t.Length
    if ($n -eq 0 -or $t[0] -ne [char]'{') {
        return $null
    }
    $space = [regex]'\G[ \t\n\r]*'
    $stringToken = [regex]'\G"(?>[^"\\\u0000-\u001f]+|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
    $scalarToken = [regex]'\G(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)'
    $members = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    $stack = New-Object 'System.Collections.Generic.List[char]'
    $key = $null
    $state = 'value'
    $opened = $false
    $steps = 0
    $pos = 0
    while ($true) {
        $steps++
        if (($steps % 1024) -eq 0 -and $Clock.ElapsedMilliseconds -ge $BudgetMS) {
            return 'budget'
        }
        $pos += $space.Match($t, $pos).Length
        if ($pos -ge $n) {
            return $null
        }
        $c = $t[$pos]
        $closed = $false
        if ($state -eq 'after') {
            $top = $stack[$stack.Count - 1]
            if ($c -eq [char]',') {
                $pos++
                $state = if ($top -eq [char]'{') { 'key' } else { 'value' }
                continue
            }
            if (($top -eq [char]'{' -and $c -eq [char]'}') -or ($top -eq [char]'[' -and $c -eq [char]']')) {
                $closed = $true
            }
            else {
                return $null
            }
        }
        elseif ($state -eq 'key') {
            if ($opened -and $c -eq [char]'}') {
                $closed = $true
            }
            else {
                $match = $stringToken.Match($t, $pos)
                if (-not $match.Success) {
                    return $null
                }
                $pos += $match.Length
                if ($stack.Count -eq 1) {
                    $key = ConvertFrom-CopilotJsonString $match.Value
                }
                $pos += $space.Match($t, $pos).Length
                if ($pos -ge $n -or $t[$pos] -ne [char]':') {
                    return $null
                }
                $pos++
                $opened = $false
                $state = 'value'
                continue
            }
        }
        elseif ($opened -and $c -eq [char]']') {
            $closed = $true
        }
        elseif ($c -eq [char]'{' -or $c -eq [char]'[') {
            $stack.Add($c)
            $pos++
            $opened = $true
            $state = if ($c -eq [char]'{') { 'key' } else { 'value' }
            continue
        }
        else {
            $opened = $false
            $value = $null
            if ($c -eq [char]'"') {
                $match = $stringToken.Match($t, $pos)
                if ($match.Success -and $stack.Count -eq 1) {
                    $value = ConvertFrom-CopilotJsonString $match.Value
                }
            }
            else {
                $match = $scalarToken.Match($t, $pos)
            }
            if (-not $match.Success) {
                return $null
            }
            $pos += $match.Length
            if ($stack.Count -eq 1) {
                $members[$key] = $value
            }
            $state = 'after'
            continue
        }
        # $closed: the innermost container ends here.
        $pos++
        $opened = $false
        $stack.RemoveAt($stack.Count - 1)
        if ($stack.Count -eq 0) {
            $pos += $space.Match($t, $pos).Length
            if ($pos -ne $n) {
                return $null
            }
            # The comma keeps PowerShell from unrolling the dictionary.
            return , $members
        }
        if ($stack.Count -eq 1) {
            $members[$key] = $null
        }
        $state = 'after'
    }
}

function ConvertFrom-CopilotJsonString {
    param([string]$Token)
    $inner = $Token.Substring(1, $Token.Length - 2)
    if ($inner.IndexOf([char]'\') -lt 0) {
        return $inner
    }
    return [regex]::Replace($inner, '\\(?:u([0-9a-fA-F]{4})|(.))', [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            if ($m.Groups[1].Success) {
                return [string][char][Convert]::ToInt32($m.Groups[1].Value, 16)
            }
            switch -CaseSensitive ($m.Groups[2].Value) {
                'b' { return [string][char]8 }
                'f' { return [string][char]12 }
                'n' { return [string][char]10 }
                'r' { return [string][char]13 }
                't' { return [string][char]9 }
                default { return $m.Groups[2].Value }
            }
        })
}

function ConvertTo-CopilotJsonString {
    param([string]$Value)
    $escaped = [regex]::Replace($Value, '["\\\u0000-\u001f\u007f\u2028\u2029\ud800-\udfff]', [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            '\u{0:x4}' -f [int][char]$m.Value
        })
    return '"' + $escaped + '"'
}

# The adapter's own denial for a child answer that denies this event, or
# $null. The adapter writes this answer, never the child's bytes, so a
# difference between this check and Copilot's parser can add a denial but
# never turn one into an allow.
function Get-CopilotChildDenial {
    param($Members, [string]$HookEvent)
    if ($HookEvent -eq 'preToolUse') {
        $decisionKey = 'permissionDecision'
        $reasonKey = 'permissionDecisionReason'
    }
    elseif ($HookEvent -eq 'permissionRequest') {
        $decisionKey = 'behavior'
        $reasonKey = 'message'
    }
    else {
        return $null
    }
    if ($Members -isnot [System.Collections.Generic.Dictionary[string, object]]) {
        return $null
    }
    $decision = $null
    if (-not $Members.TryGetValue($decisionKey, [ref]$decision) -or $decision -isnot [string] -or $decision -cne 'deny') {
        return $null
    }
    $answer = '{"' + $decisionKey + '":"deny"'
    $reason = $null
    if ($Members.TryGetValue($reasonKey, [ref]$reason) -and $reason -is [string]) {
        $answer += ',"' + $reasonKey + '":' + (ConvertTo-CopilotJsonString $reason)
    }
    return $answer + '}'
}

try {
    if (-not (Test-Path -LiteralPath $hook -PathType Leaf)) {
        throw "DefenseClaw hook launcher is missing: $hook"
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # Windows PowerShell's .NET Framework Process API has no
    # ProcessStartInfo.StandardInputEncoding property. Process instead builds
    # its redirected readers/writer from these console encodings. Set them
    # before ReadToEnd so Copilot's UTF-8 JSON is decoded as UTF-8, not the
    # console default.
    [Console]::InputEncoding = $utf8NoBom
    [Console]::OutputEncoding = $utf8NoBom
    $payload = [Console]::In.ReadToEnd()
    # Windows PowerShell 5.1 materializes the redirected-stream encoding marker
    # as U+FEFF even when the original Copilot JSON bytes had no BOM. JSON must
    # begin with the object itself, so remove exactly one leading marker while
    # preserving every byte of the event body after it.
    if ($payload.Length -gt 0 -and $payload[0] -eq [char]0xFEFF) {
        $payload = $payload.Substring(1)
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $hook
    $startInfo.Arguments = 'hook --connector copilot --event ' + $Event
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'DefenseClaw hook launcher did not start'
    }
    $started = $true
    # Child stdin budget starts after the launcher exists. PowerShell 5.1
    # startup must not steal the hook-input window, or a busy CI host
    # fail-opens as "timed out while receiving input".
    $deadline.Restart()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    # stdout/stderr are already being drained, so a small synchronous write
    # cannot deadlock. Waiting on a LongRunning Task previously burned the
    # remaining budget when the pool was slow to schedule the writer.
    $process.StandardInput.AutoFlush = $true
    $process.StandardInput.Write($payload)
    $process.StandardInput.Close()
    $stdinClosed = $true

    $remainingMS = $timeoutMS - [int]$deadline.ElapsedMilliseconds
    if ($remainingMS -le 0 -or -not $process.WaitForExit($remainingMS)) {
        throw "DefenseClaw hook launcher timed out after ${timeoutMS}ms"
    }
    $remainingMS = $timeoutMS - [int]$deadline.ElapsedMilliseconds
    if ($remainingMS -le 0 -or -not $stdoutTask.Wait($remainingMS)) {
        throw "DefenseClaw hook launcher timed out after ${timeoutMS}ms while reading output"
    }
    $remainingMS = $timeoutMS - [int]$deadline.ElapsedMilliseconds
    if ($remainingMS -le 0 -or -not $stderrTask.Wait($remainingMS)) {
        throw "DefenseClaw hook launcher timed out after ${timeoutMS}ms while reading diagnostics"
    }

    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
        # A launcher that wrote one complete denial for this event before
        # exiting nonzero has decided: answer with that denial in either fail
        # mode. Any other output with a nonzero status is a failure. A check
        # that cannot finish inside the budget is doubt, and doubt denies.
        $denial = $null
        if ($Event -eq 'preToolUse' -or $Event -eq 'permissionRequest') {
            $members = Read-CopilotAnswerMembers -Text $stdout -Clock $deadline -BudgetMS $timeoutMS
            if ($members -is [string]) {
                $answerUnchecked = $true
                throw "DefenseClaw hook launcher exited with status $($process.ExitCode); its answer could not be checked within ${timeoutMS}ms"
            }
            $denial = Get-CopilotChildDenial -Members $members -HookEvent $Event
        }
        if ($null -eq $denial) {
            throw "DefenseClaw hook launcher exited with status $($process.ExitCode)"
        }
        $stdout = $denial + [System.Environment]::NewLine
    }
    if ($stdout.Length -gt 0) {
        [Console]::Out.Write($stdout)
    }
    if ($stderr.Length -gt 0) {
        [Console]::Error.Write($stderr)
    }
}
catch {
    $deny = $failClosed -or $answerUnchecked
    if ($deny -and $Event -eq 'preToolUse') {
        [Console]::Out.WriteLine('{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}')
    }
    elseif ($deny -and $Event -eq 'permissionRequest') {
        [Console]::Out.WriteLine('{"behavior":"deny","message":"DefenseClaw hook failed closed"}')
    }
    $mode = if ($deny) { 'closed' } else { 'open' }
    [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed ' + $mode + ': ' + $_.Exception.Message)
}
finally {
    if ($started -and -not $process.HasExited) {
        try {
            # Kill() only starts termination. Wait briefly: this wait and the
            # exit below share the reserve left after $timeoutMS inside
            # Copilot's 30-second hook budget.
            $process.Kill()
            [void]$process.WaitForExit(2000)
        }
        catch {
            [Console]::Error.WriteLine('defenseclaw: could not stop failed Copilot hook launcher: ' + $_.Exception.Message)
        }
    }
    if ($started -and -not $stdinClosed) {
        try {
            $process.StandardInput.Close()
        }
        catch {
            [Console]::Error.WriteLine('defenseclaw: could not close failed Copilot hook input: ' + $_.Exception.Message)
        }
    }
    if ($null -ne $process) {
        $process.Dispose()
    }
    $deadline.Stop()
}

[Console]::Out.Flush()
[Console]::Error.Flush()
# Exit through the console host. Windows PowerShell 5.1 spends seconds in
# runtime shutdown after [System.Environment]::Exit (about 3s on an idle host,
# more on a busy one), and Copilot counts that time against the hook budget.
# Hosts that do not support SetShouldExit keep the forced exit.
try {
    $Host.SetShouldExit(0)
}
catch {
    [System.Environment]::Exit(0)
}
