# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A committed lifecycle can leave its managed-hook lifecycle journal behind
# when the installed gateway refuses to collect an old runtime generation (a
# release before GAP-1322 refuses the contractless Kiro bundles 1.0.1 wrote).
# Every later Setup upgrade, ensure and uninstall then failed retiring it
# with that same installed gateway. A standalone lifecycle now removes that
# exact journal, records why, and goes on; any other retire failure, a
# pending transaction or the Secure Client profile keeps the error. The
# teardown journal of a refused or rolled-back uninstall goes the same way
# (GAP-1041). So does a journal whose retire stopped at a per-user folder the
# installed gateway could not trust, which rolled back every later upgrade
# with 1603 (#1105, GAP-0781); with a pending transaction that refusal keeps
# naming the remedy. Only the error in the gateway's own retire report counts:
# the same text from another failure, another phase or another report error
# keeps the journal and the error. The gateway command is stubbed; runs in a
# disposable scratch directory.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-stale-lifecycle-journal-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $layout = @{
            ManagedHooksLifecycleJournalPath = [IO.Path]::Combine($Root, 'managed-hooks-lifecycle-journal.json')
            PendingPath = [IO.Path]::Combine($Root, 'pending.json')
        }
        # Each is the error the installed gateway puts in its retire report.
        $gcRefusal = 'retire kiro managed runtime generations for SID S-1-5-21-1-2-3-1017: enterprise hooks: refusing to collect an invalid managed runtime bundle'
        $untrustedFolder = 'retire claudecode managed runtime generations for SID S-1-5-21-1-2-3-1103 (CONTOSO\stale): enterprise hooks: managed runtime generation directory is untrusted: C:\Users\stale\.defenseclaw\hooks: access denied'
        $script:TestRetireError = ''
        $script:TestRetireShape = 'report'
        function Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand {
            param([hashtable]$Layout, [string]$GatewayServiceName, [string]$Action)
            if ($Action -cne 'retire') {
                throw "unexpected action $Action"
            }
            if ($script:TestRetireError) {
                $text = "managed-hook lifecycle snapshot retire failed: $($script:TestRetireError)"
                if ($script:TestRetireShape -ceq 'plain') {
                    # Not from a gateway report (running the command, reading
                    # its output, another step).
                    throw $text
                }
                $exception = [Management.Automation.RuntimeException]::new($text)
                $exception.Data['DefenseClawLifecycleAction'] = if ($script:TestRetireShape -ceq 'phase') { 'capture' } else { 'retire' }
                $exception.Data['DefenseClawLifecycleReportError'] = $script:TestRetireError
                throw $exception
            }
            [IO.File]::Delete($Layout.ManagedHooksLifecycleJournalPath)
            return [pscustomobject]@{ ok = $true }
        }
        $run = {
            param([string]$Name, [string]$EnterpriseProfile, [string]$RetireError, [bool]$Pending, [bool]$WantThrow, [bool]$WantRemoved, [string]$Shape = 'report')
            $script:TestRetireShape = $Shape
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $EnterpriseProfile
            [IO.File]::WriteAllText($layout.ManagedHooksLifecycleJournalPath, '{"schema_version":4,"phase":"captured"}')
            if ($Pending) {
                [IO.File]::WriteAllText($layout.PendingPath, '{}')
            }
            $script:TestRetireError = $RetireError
            $script:DefenseClawStaleLifecycleJournalRemoved = ''
            $threw = $false
            try {
                Invoke-DefenseClawCommittedManagedHooksLifecycleRetire `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway'
            }
            catch {
                $threw = $true
                # A refusal may name the remedy before the gateway's error.
                if (-not ([string]$_.Exception.Message).Contains($RetireError)) {
                    $failures.Add("${Name}: error changed to '$($_.Exception.Message)'")
                }
            }
            $removed = -not [IO.File]::Exists($layout.ManagedHooksLifecycleJournalPath)
            if ($threw -ne $WantThrow) {
                $failures.Add("${Name}: threw=$threw, want $WantThrow")
            }
            if ($removed -ne $WantRemoved) {
                $failures.Add("${Name}: journal removed=$removed, want $WantRemoved")
            }
            $recorded = -not [string]::IsNullOrEmpty($script:DefenseClawStaleLifecycleJournalRemoved)
            $wantRecorded = $WantRemoved -and -not [string]::IsNullOrEmpty($RetireError)
            if ($recorded -ne $wantRecorded) {
                $failures.Add("${Name}: removal recorded=$recorded, want $wantRecorded")
            }
            [IO.File]::Delete($layout.ManagedHooksLifecycleJournalPath)
            [IO.File]::Delete($layout.PendingPath)
        }
        try {
            & $run 'retired' 'Standalone' '' $false $false $true
            & $run 'legacy bundle refused' 'Standalone' $gcRefusal $false $false $true
            & $run 'other retire failure' 'Standalone' 'deployment managed-hook activation binding is invalid' $false $true $false
            & $run 'pending transaction' 'Standalone' $gcRefusal $true $true $false
            & $run 'Secure Client' 'SecureClient' $gcRefusal $false $true $false
            & $run 'untrusted per-user folder' 'Standalone' $untrustedFolder $false $false $true
            & $run 'untrusted per-user folder, pending transaction' 'Standalone' $untrustedFolder $true $true $false
            & $run 'untrusted per-user folder, Secure Client' 'SecureClient' $untrustedFolder $false $true $false
            # The same text, but not the gateway's retire-collection refusal.
            & $run 'untrusted text outside a gateway report' 'Standalone' $untrustedFolder $false $true $false 'plain'
            & $run 'untrusted text in another phase' 'Standalone' $untrustedFolder $false $true $false 'phase'
            & $run 'untrusted text in another retire error' 'Standalone' 'deployment managed-hook activation binding is invalid: enterprise hooks: managed runtime generation directory is untrusted: C:\ProgramData\x' $false $true $false
            & $run 'untrusted text after another collection error' 'Standalone' 'retire claudecode managed runtime generations for SID S-1-5-21-1-2-3-1103: open C:\Users\x: enterprise hooks: managed runtime generation directory is untrusted: C:\Users\x' $false $true $false
            & $run 'legacy bundle text outside a gateway report' 'Standalone' $gcRefusal $false $true $false 'plain'

            # GAP-1041: the teardown journal of a rolled-back uninstall goes
            # (and -Stale reports it); another phase, or a pending
            # transaction, keeps it.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            $layout['ManagedHooksTeardownJournalPath'] = [IO.Path]::Combine($Root, 'managed-hooks-teardown-journal.json')
            foreach ($case in @(
                    @('rolled_back', $false, $true),
                    @('prepared', $false, $false),
                    @('rolled_back', $true, $false)
                )) {
                [IO.File]::WriteAllText($layout.ManagedHooksTeardownJournalPath, ('{"schema_version":6,"phase":"' + $case[0] + '"}'))
                if ($case[1]) {
                    [IO.File]::WriteAllText($layout.PendingPath, '{}')
                }
                $script:DefenseClawStaleTeardownJournalRemoved = ''
                $removed = Remove-DefenseClawRolledBackTeardownJournal -Layout $layout -Stale
                $gone = -not [IO.File]::Exists($layout.ManagedHooksTeardownJournalPath)
                $reported = -not [string]::IsNullOrEmpty($script:DefenseClawStaleTeardownJournalRemoved)
                if ($removed -ne $case[2] -or $gone -ne $case[2] -or $reported -ne $case[2]) {
                    $failures.Add("teardown journal $($case[0]) pending=$($case[1]): removed=$removed gone=$gone reported=$reported, want $($case[2])")
                }
                [IO.File]::Delete($layout.ManagedHooksTeardownJournalPath)
                [IO.File]::Delete($layout.PendingPath)
            }
        }
        finally {
            $script:TestRetireShape = 'report'
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
            $script:DefenseClawStaleLifecycleJournalRemoved = ''
            $script:DefenseClawStaleTeardownJournalRemoved = ''
        }
        return , $failures
    } $root
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-stale-lifecycle-journal-smoke: OK'
