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
$deadline = [System.Diagnostics.Stopwatch]::StartNew()

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
        # exiting nonzero has decided: forward it in either fail mode. Any
        # other output with a nonzero status is a failure.
        $denial = $null
        $text = $stdout.Trim()
        if ($text.StartsWith('{') -and $text.EndsWith('}')) {
            try {
                $denial = ConvertFrom-Json -InputObject $text -ErrorAction Stop
            }
            catch {
                $denial = $null
            }
        }
        $denied = ($denial -is [System.Management.Automation.PSCustomObject]) -and (
            ($Event -eq 'preToolUse' -and $denial.permissionDecision -ceq 'deny') -or
            ($Event -eq 'permissionRequest' -and $denial.behavior -ceq 'deny'))
        if (-not $denied) {
            throw "DefenseClaw hook launcher exited with status $($process.ExitCode)"
        }
    }
    if ($stdout.Length -gt 0) {
        [Console]::Out.Write($stdout)
    }
    if ($stderr.Length -gt 0) {
        [Console]::Error.Write($stderr)
    }
}
catch {
    if ($failClosed -and $Event -eq 'preToolUse') {
        [Console]::Out.WriteLine('{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}')
    }
    elseif ($failClosed -and $Event -eq 'permissionRequest') {
        [Console]::Out.WriteLine('{"behavior":"deny","message":"DefenseClaw hook failed closed"}')
    }
    $mode = if ($failClosed) { 'closed' } else { 'open' }
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
