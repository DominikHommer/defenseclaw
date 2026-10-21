# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Standalone lifecycle regressions of the 1.0.4 Windows fix wave: an
# uninstall refuses a link in its state folder before it changes anything
# (GAP-0145), the InstallRoot retirement rename waits out a short-lived
# holder (GAP-0149), a reinstall accepts the retained redaction key the
# deleted gateway service still held (GAP-0152), a run that starts while a
# purge removes the lifecycle lock gets a new protected one (GAP-1076), and
# the vendor directory check and grant handle an administrator's own entry,
# INTERACTIVE-only grants and group denies (GAP-0867, GAP-1439, GAP-1142).
# Review fixes: the uninstall proves the InstallRoot rename before it
# commits, a full standalone purge keeps a selector shared with another
# deployment and works under the selector lock, and a deny for an account
# that is not enrolled or no longer exists does not block the vendor check.
# Loop round 1: a deny for a domain SID the lookup cannot map still counts
# (only this computer's own SAM proves a SID retired), and a program that
# opens a file in InstallRoot after the pre-commit probe defers the
# retirement to the finalizer instead of failing the committed uninstall.
# Runs elevated in a disposable directory; no service or machine root is
# touched.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop

$root = [IO.Path]::Combine([IO.Path]::GetFullPath($ScratchRoot), ('dc-w2b-win-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)))
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root, [string]$ModulePath)
        $failures = [Collections.Generic.List[string]]::new()
        $savedProgramData = $script:ProgramData
        $savedProfile = Get-DefenseClawEnterpriseProfile
        $savedRetry = $script:InstallRootRetirementRetryMilliseconds
        $savedSelectorTimeout = $script:RuntimeSelectorLockTimeoutSeconds
        $engine = [IO.Path]::Combine($PSHOME, $(if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' }))
        function Start-TestHolder([string]$Path, [string]$Mode, [int]$HoldMilliseconds) {
            # A child process that opens Path (Read: shared read; DeleteOnClose:
            # exclusive with delete-on-close, as a purge does) and holds it.
            $ready = [IO.Path]::Combine($Root, 'ready-' + [Guid]::NewGuid().ToString('N'))
            $script = [IO.Path]::Combine($Root, 'holder-' + [Guid]::NewGuid().ToString('N') + '.ps1')
            [IO.File]::WriteAllText($script, @'
param([string]$Path, [string]$Mode, [string]$Ready, [int]$HoldMilliseconds)
if ($Mode -eq 'DeleteOnClose') {
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 1, [IO.FileOptions]::DeleteOnClose)
}
else {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
}
[IO.File]::WriteAllText($Ready, 'ready')
Start-Sleep -Milliseconds $HoldMilliseconds
$stream.Dispose()
'@)
            $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Path "{1}" -Mode {2} -Ready "{3}" -HoldMilliseconds {4}' -f $script, $Path, $Mode, $ready, $HoldMilliseconds
            $process = Microsoft.PowerShell.Management\Start-Process -FilePath $engine -ArgumentList $arguments -WindowStyle Hidden -PassThru
            $clock = [Diagnostics.Stopwatch]::StartNew()
            while (-not [IO.File]::Exists($ready)) {
                if ($process.HasExited -or $clock.ElapsedMilliseconds -gt 60000) {
                    throw "test holder of $Path did not open it"
                }
                Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 50
            }
            return $process
        }
        $protected = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        $rootSecurity = [Security.AccessControl.DirectorySecurity]::new()
        $rootSecurity.SetSecurityDescriptorSddlForm($protected, [Security.AccessControl.AccessControlSections]::All)
        Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Root -AclObject $rootSecurity
        $script:ProgramData = $Root
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            # GAP-0145: a junction in StateRoot is refused before anything
            # changes, naming how to remove only the link.
            $state = [IO.Path]::Combine($Root, 'state')
            $target = [IO.Path]::Combine($Root, 'junction-target')
            [void][IO.Directory]::CreateDirectory($state)
            [void][IO.Directory]::CreateDirectory($target)
            $junction = [IO.Path]::Combine($state, 'secrets')
            [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $junction -Target $target)
            try {
                Assert-DefenseClawUninstallStateTreeNoReparse -Layout @{ StateRoot = $state }
                $failures.Add('a junction in StateRoot passed the uninstall preflight')
            }
            catch {
                if ($_.Exception.Message -notlike '*stopped before it changed anything*' -or $_.Exception.Message -notlike '*rmdir*') {
                    $failures.Add("junction refusal: $($_.Exception.Message)")
                }
            }
            [IO.Directory]::Delete($junction)
            Assert-DefenseClawUninstallStateTreeNoReparse -Layout @{ StateRoot = $state }
            # The preflight runs before the uninstall transaction.
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
            $uninstall = $ast.Find({
                    param($node)
                    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-DefenseClawUninstallLifecycle'
                }, $true)
            $calls = @($uninstall.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
            $preflight = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Assert-DefenseClawUninstallStateTreeNoReparse' })
            $transaction = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'New-DefenseClawTransaction' })
            if ($preflight.Count -ne 1 -or $transaction.Count -lt 1 -or
                $preflight[0].Extent.StartOffset -ge $transaction[0].Extent.StartOffset) {
                $failures.Add('the StateRoot link preflight does not run before the uninstall transaction')
            }

            # GAP-0149: the retirement rename waits for a program that holds a
            # file in InstallRoot for a moment; another failure is immediate.
            $install = [IO.Path]::Combine($Root, 'install')
            $binary = [IO.Path]::Combine($install, 'bin', 'defenseclaw-hook.exe')
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($binary))
            [IO.File]::WriteAllText($binary, 'stand-in')
            $script:InstallRootRetirementRetryMilliseconds = 30000
            $holder = Start-TestHolder -Path $binary -Mode Read -HoldMilliseconds 2000
            $retired = [IO.Path]::Combine($Root, 'install-retired')
            try {
                Move-DefenseClawInstallRootForRetirement -Source $install -Destination $retired
                if (-not [IO.Directory]::Exists($retired) -or [IO.Directory]::Exists($install)) {
                    $failures.Add('the retirement rename did not complete after the holder exited')
                }
            }
            catch {
                $failures.Add("the retirement rename failed while a holder was briefly open: $($_.Exception.Message)")
            }
            finally {
                [void]$holder.WaitForExit(30000)
            }
            $clock = [Diagnostics.Stopwatch]::StartNew()
            try {
                Move-DefenseClawInstallRootForRetirement -Source ([IO.Path]::Combine($Root, 'absent')) -Destination ([IO.Path]::Combine($Root, 'absent-retired'))
                $failures.Add('renaming a missing InstallRoot succeeded')
            }
            catch {
                if ($clock.ElapsedMilliseconds -gt 10000) {
                    $failures.Add('a missing InstallRoot was retried as if it were in use')
                }
            }

            # Review of GAP-0149: the uninstall renames InstallRoot aside and
            # back before it commits. A free InstallRoot ends up in place; a
            # holder that outlasts the window stops the uninstall there, with
            # InstallRoot in place and nothing retired.
            $probe = [IO.Path]::Combine($Root, 'probe-install')
            $probeRetired = [IO.Path]::Combine($Root, 'probe-install-retired')
            $probeBinary = [IO.Path]::Combine($probe, 'bin', 'defenseclaw-hook.exe')
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($probeBinary))
            [IO.File]::WriteAllText($probeBinary, 'stand-in')
            try {
                Assert-DefenseClawInstallRootRetirable -Source $probe -Destination $probeRetired
                if (-not [IO.File]::Exists($probeBinary) -or [IO.Directory]::Exists($probeRetired)) {
                    $failures.Add('the pre-commit retirement probe did not put InstallRoot back')
                }
            }
            catch {
                $failures.Add("the pre-commit retirement probe failed on a free InstallRoot: $($_.Exception.Message)")
            }
            $script:InstallRootRetirementRetryMilliseconds = 1000
            $holder = Start-TestHolder -Path $probeBinary -Mode Read -HoldMilliseconds 8000
            try {
                Assert-DefenseClawInstallRootRetirable -Source $probe -Destination $probeRetired
                $failures.Add('the pre-commit retirement probe passed while a program held InstallRoot')
            }
            catch {
                if ($_.Exception.Message -notlike '*stopped before it removed anything*' -or
                    -not [IO.File]::Exists($probeBinary) -or [IO.Directory]::Exists($probeRetired)) {
                    $failures.Add("the held InstallRoot probe: $($_.Exception.Message)")
                }
            }
            finally {
                [void]$holder.WaitForExit(30000)
            }
            $probeCalls = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Assert-DefenseClawInstallRootRetirable' })
            $commit = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Complete-DefenseClawTransaction' })
            if ($probeCalls.Count -ne 1 -or $commit.Count -lt 1 -or
                $probeCalls[0].Extent.StartOffset -le $transaction[0].Extent.StartOffset -or
                $probeCalls[0].Extent.StartOffset -ge $commit[0].Extent.StartOffset) {
                $failures.Add('the InstallRoot retirement probe does not run inside the uninstall transaction before its commit')
            }

            # Loop round 1: a program that opens a file in InstallRoot after
            # the probe passed, and holds it past the retry window, no longer
            # fails the committed retirement: it is deferred, with InstallRoot
            # in place. A free InstallRoot is retired, and a missing one is
            # still an error.
            $late = [IO.Path]::Combine($Root, 'late-install')
            $lateRetired = [IO.Path]::Combine($Root, 'late-install-retired')
            $lateBinary = [IO.Path]::Combine($late, 'bin', 'defenseclaw-hook.exe')
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($lateBinary))
            [IO.File]::WriteAllText($lateBinary, 'stand-in')
            $script:InstallRootRetirementRetryMilliseconds = 1000
            Assert-DefenseClawInstallRootRetirable -Source $late -Destination $lateRetired
            $holder = Start-TestHolder -Path $lateBinary -Mode Read -HoldMilliseconds 8000
            try {
                $deferred = Invoke-DefenseClawCommittedInstallRootRetirement -Source $late -Destination $lateRetired
                if ([string]::IsNullOrEmpty($deferred) -or -not [IO.File]::Exists($lateBinary) -or [IO.Directory]::Exists($lateRetired)) {
                    $failures.Add("a holder that opened InstallRoot after the probe was not deferred: '$deferred'")
                }
            }
            catch {
                $failures.Add("a holder that opened InstallRoot after the probe failed the committed retirement: $($_.Exception.Message)")
            }
            finally {
                [void]$holder.WaitForExit(30000)
            }
            try {
                $deferred = Invoke-DefenseClawCommittedInstallRootRetirement -Source $late -Destination $lateRetired
                if (-not [string]::IsNullOrEmpty($deferred) -or [IO.Directory]::Exists($late) -or -not [IO.Directory]::Exists($lateRetired)) {
                    $failures.Add("a free InstallRoot was not retired after the commit: '$deferred'")
                }
            }
            catch {
                $failures.Add("a free InstallRoot failed the committed retirement: $($_.Exception.Message)")
            }
            try {
                [void](Invoke-DefenseClawCommittedInstallRootRetirement -Source ([IO.Path]::Combine($Root, 'absent')) -Destination ([IO.Path]::Combine($Root, 'absent-retired')))
                $failures.Add('a missing InstallRoot was deferred instead of failing')
            }
            catch {
                Microsoft.PowerShell.Utility\Write-Verbose "missing InstallRoot refused: $($_.Exception.Message)"
            }
            # The uninstall runs that retirement after its commit, never the
            # bare rename, and hands a deferred one to the finalizer before it
            # retires the teardown journal.
            $committedRetirement = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Invoke-DefenseClawCommittedInstallRootRetirement' })
            $bareRename = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Move-DefenseClawInstallRootForRetirement' })
            $deferStart = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Start-DefenseClawDeferredSelfUninstallRetirement' })
            $journalRetire = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Remove-DefenseClawCommittedManagedHooksTeardownJournal' })
            if ($committedRetirement.Count -ne 1 -or $bareRename.Count -ne 0 -or $deferStart.Count -ne 1 -or $journalRetire.Count -lt 1 -or
                $committedRetirement[0].Extent.StartOffset -le $commit[0].Extent.StartOffset -or
                $deferStart[0].Extent.StartOffset -le $committedRetirement[0].Extent.StartOffset -or
                $deferStart[0].Extent.StartOffset -ge $journalRetire[0].Extent.StartOffset) {
                $failures.Add('the committed uninstall does not defer a held InstallRoot to the finalizer before the journal retirement')
            }
            # The finalizer of a deferred retirement runs the module from
            # InstallRoot while the retired one is not there; the usual
            # finalizer content is unchanged (the retired module only).
            $helperLayout = @{ SelfUninstallReceiptPath = 'C:\ProgramData\Cisco\DefenseClaw-Lifecycle\self-uninstall-0.json' }
            $helperReceipt = [pscustomobject]@{
                install_root = 'C:\Program Files\Cisco\DefenseClaw'
                retired_install_root = 'C:\Program Files\Cisco\DefenseClaw.retired-0'
                retired_module_sha256 = ('0' * 64)
            }
            $usual = Get-DefenseClawSelfUninstallHelperContent -Layout $helperLayout -Receipt $helperReceipt
            $deferredContent = Get-DefenseClawSelfUninstallHelperContent -Layout $helperLayout -Receipt $helperReceipt -DeferredRetirement
            $canonicalModule = "'C:\Program Files\Cisco\DefenseClaw\libexec\DefenseClawEnterprise.psm1'"
            foreach ($content in @($usual, $deferredContent)) {
                $parseErrors = $null
                [void][Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$parseErrors)
                if (@($parseErrors).Count -gt 0) {
                    $failures.Add("a self-uninstall finalizer does not parse: $($parseErrors -join '; ')")
                }
            }
            if ($usual.Contains($canonicalModule) -or -not $deferredContent.Contains($canonicalModule) -or
                $usual.Replace("`r", '') -cne $deferredContent.Replace("`r", '').Replace(
                    "; if (-not [IO.File]::Exists(`$modulePath)) { `$modulePath = $canonicalModule }", '')) {
                $failures.Add('the deferred finalizer is not the usual one plus the InstallRoot module')
            }

            # GAP-1076: a run waiting for the lock while a purge holds it
            # with delete-on-close gets a new protected lock afterwards.
            $lockDirectory = [IO.Path]::Combine($Root, 'Cisco', 'DefenseClaw-Lifecycle')
            $lockLayout = @{
                LifecycleLockDirectory = $lockDirectory
                LifecycleLockPath = [IO.Path]::Combine($lockDirectory, 'lifecycle.lock')
            }
            Initialize-DefenseClawManagedRoot -Path $lockDirectory -Label 'lifecycle lock directory' -RequiredBase $Root
            Exit-DefenseClawLifecycleLock -Lock (Enter-DefenseClawLifecycleLock -Layout $lockLayout -TimeoutSeconds 10)
            $purge = Start-TestHolder -Path $lockLayout.LifecycleLockPath -Mode DeleteOnClose -HoldMilliseconds 1500
            try {
                $lock = Enter-DefenseClawLifecycleLock -Layout $lockLayout -TimeoutSeconds 20
                Exit-DefenseClawLifecycleLock -Lock $lock
                if (-not [IO.File]::Exists($lockLayout.LifecycleLockPath)) {
                    $failures.Add('the new lifecycle lock is missing')
                }
            }
            catch {
                $failures.Add("a run that started while a purge removed the lock did not get one: $($_.Exception.Message)")
            }
            finally {
                [void]$purge.WaitForExit(30000)
            }

            # Loop round 1: the finalizer of a deferred retirement renames
            # InstallRoot once per pass under the lifecycle lock, waits for a
            # holder outside it, then commits; a holder that outlasts its
            # deadline leaves InstallRoot and the receipt for the next
            # Uninstall, and a receipt another run finished is left alone.
            $deferInstall = [IO.Path]::Combine($Root, 'defer-install')
            $deferRetired = [IO.Path]::Combine($Root, 'defer-install-retired')
            $deferBinary = [IO.Path]::Combine($deferInstall, 'bin', 'defenseclaw-hook.exe')
            $deferLayout = @{
                InstallRoot = $deferInstall
                LifecycleLockDirectory = $lockLayout.LifecycleLockDirectory
                LifecycleLockPath = $lockLayout.LifecycleLockPath
            }
            $stubbed = @(
                'Get-DefenseClawSelfUninstallReceipt',
                'Test-DefenseClawSelfUninstallCallerRunning',
                'Assert-DefenseClawDeferredRetirementState',
                'Complete-DefenseClawCommittedManagedHooksFinalization',
                'Complete-DefenseClawRetiredSelfUninstallCommit'
            )
            $savedFunctions = @{}
            foreach ($name in $stubbed) {
                $savedFunctions[$name] = (Microsoft.PowerShell.Management\Get-Item -LiteralPath "function:$name").ScriptBlock
            }
            $script:TestDeferredCommits = 0
            $script:TestDeferredReceipt = $null
            try {
                function script:Get-DefenseClawSelfUninstallReceipt { param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$Required) return $script:TestDeferredReceipt }
                function script:Test-DefenseClawSelfUninstallCallerRunning { param($Layout, $Receipt) return $false }
                function script:Assert-DefenseClawDeferredRetirementState { param($Layout, $Receipt) }
                function script:Complete-DefenseClawCommittedManagedHooksFinalization { param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$Purge, [switch]$NativeSealed) }
                function script:Complete-DefenseClawRetiredSelfUninstallCommit {
                    param($Layout, $Receipt)
                    $script:TestDeferredCommits++
                    $script:TestDeferredReceipt.phase = 'committed_install_retirement'
                }
                function New-TestDeferredRoot {
                    if ([IO.Directory]::Exists($deferRetired)) {
                        [IO.Directory]::Delete($deferRetired, $true)
                    }
                    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($deferBinary))
                    [IO.File]::WriteAllText($deferBinary, 'stand-in')
                    $script:TestDeferredCommits = 0
                    $script:TestDeferredReceipt = [pscustomobject]@{
                        phase = 'prepared_install_retirement'
                        retired_install_root = $deferRetired
                        gateway_service = 'DefenseClawW2BSmokeAbsent'
                        guardian_service = 'DefenseClawW2BSmokeGuardianAbsent'
                        purge_requested = $false
                    }
                }
                New-TestDeferredRoot
                $holder = Start-TestHolder -Path $deferBinary -Mode Read -HoldMilliseconds 3000
                $clock = [Diagnostics.Stopwatch]::StartNew()
                try {
                    $outcome = Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $deferLayout -Receipt $script:TestDeferredReceipt -Deadline ([DateTime]::UtcNow.AddSeconds(60)) -RetryIntervalMilliseconds 200
                    if ($outcome -cne 'retired' -or [IO.Directory]::Exists($deferInstall) -or -not [IO.Directory]::Exists($deferRetired) -or
                        $script:TestDeferredCommits -ne 1 -or $clock.ElapsedMilliseconds -lt 1000) {
                        $failures.Add("the deferred retirement did not wait out the holder and commit once: $outcome, commits $($script:TestDeferredCommits), $($clock.ElapsedMilliseconds) ms")
                    }
                }
                catch {
                    $failures.Add("the deferred retirement failed while a holder was briefly open: $($_.Exception.Message)")
                }
                finally {
                    [void]$holder.WaitForExit(30000)
                }
                New-TestDeferredRoot
                $holder = Start-TestHolder -Path $deferBinary -Mode Read -HoldMilliseconds 8000
                try {
                    [void](Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $deferLayout -Receipt $script:TestDeferredReceipt -Deadline ([DateTime]::UtcNow.AddSeconds(1)) -RetryIntervalMilliseconds 200)
                    $failures.Add('the deferred retirement passed while a holder outlasted its deadline')
                }
                catch {
                    if ($_.Exception.Message -notlike '*next Uninstall finishes it*' -or -not [IO.File]::Exists($deferBinary) -or
                        [IO.Directory]::Exists($deferRetired) -or $script:TestDeferredCommits -ne 0 -or
                        [string]$script:TestDeferredReceipt.phase -cne 'prepared_install_retirement') {
                        $failures.Add("a holder past the deadline: $($_.Exception.Message)")
                    }
                }
                finally {
                    [void]$holder.WaitForExit(30000)
                }
                $script:TestDeferredReceipt.phase = 'committed_install_retirement'
                if ((Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $deferLayout -Receipt $script:TestDeferredReceipt -Deadline ([DateTime]::UtcNow.AddSeconds(5))) -cne 'not_deferred' -or
                    -not [IO.File]::Exists($deferBinary)) {
                    $failures.Add('the finalizer renamed InstallRoot for a receipt another run committed')
                }
                $script:TestDeferredReceipt = $null
                if ((Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $deferLayout -Receipt ([pscustomobject]@{ gateway_service = 'a'; guardian_service = 'b' }) -Deadline ([DateTime]::UtcNow.AddSeconds(5))) -cne 'finished' -or
                    -not [IO.File]::Exists($deferBinary)) {
                    $failures.Add('the finalizer acted on a receipt another run finished')
                }
            }
            finally {
                foreach ($name in $stubbed) {
                    Microsoft.PowerShell.Management\Set-Item -Path "function:script:$name" -Value $savedFunctions[$name]
                }
            }

            # GAP-0867: an administrator's identical Users entry survives
            # install and uninstall.
            function Set-TestDirectorySddl([string]$Path, [string]$Sddl) {
                [void][IO.Directory]::CreateDirectory($Path)
                $security = [Security.AccessControl.DirectorySecurity]::new()
                $security.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]::All)
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $security
            }
            $vendor = [IO.Path]::Combine($Root, 'vendor')
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)'
            $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before) {
                $failures.Add("uninstall removed the administrator's own Users entry from the vendor directory")
            }
            # GAP-1439: INTERACTIVE alone is not every enrolled token.
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;IU)'
            if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                $failures.Add('an INTERACTIVE-only entry counted as access for every enrolled user')
            }
            # GAP-1142: a deny for a domain group removes access; one for a
            # service SID does not.
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(D;;0x1200a0;;;S-1-5-21-1000-2000-3000-513)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)'
            if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                $failures.Add('a group deny entry was not detected')
            }
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(D;;0x1200a0;;;S-1-5-80-1-2-3-4-5)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)'
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor)) {
                $failures.Add('a service SID deny entry blocked the users check')
            }
            # Review of GAP-1142: a deny for an account of this computer that
            # no one has (a retired local user) beside a valid Users entry
            # does not block, so Grant converges; a deny for a built-in group
            # or for an enrolled user (this account, which has a profile here)
            # still does. Loop round 1: a domain SID the lookup does not map
            # (a custom domain group above RID 999, while the domain
            # controller does not answer) counts, since an enrolled user's
            # token can hold it.
            $nativeSecurity = Initialize-DefenseClawNativeSecurity
            function Get-TestSidUse([string]$Sid) {
                $identifier = [Security.Principal.SecurityIdentifier]::new($Sid)
                $bytes = [byte[]]::new($identifier.BinaryLength)
                $identifier.GetBinaryForm($bytes, 0)
                return $nativeSecurity::LookupSidUse($bytes)
            }
            $unmappedDomainGroup = 'S-1-5-21-1000-2000-3000-1234'
            $unmappedUse = Get-TestSidUse $unmappedDomainGroup
            if ($unmappedUse -ne 0) {
                $failures.Add("the lookup of an unknown domain SID returned $unmappedUse, not none-mapped")
            }
            if (-not (Test-DefenseClawUserTokenDenySID -SID $unmappedDomainGroup)) {
                $failures.Add('a deny for an unmapped domain group above RID 999 was treated as a retired account')
            }
            Set-TestDirectorySddl $vendor ('O:BAG:BAD:P(D;;0x1200a0;;;' + $unmappedDomainGroup + ')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)')
            if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                $failures.Add('a deny entry for an unmapped domain group did not block the users check')
            }
            $accountDomain = Get-DefenseClawAccountDomainSID
            if ($accountDomain -cnotmatch '^S-1-5-21-\d+-\d+-\d+$') {
                $failures.Add("this computer's account domain SID was not read: '$accountDomain'")
            }
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
            if ($currentUser.Name -like "$env:COMPUTERNAME\*" -and $null -ne $currentUser.User.AccountDomainSid -and
                $currentUser.User.AccountDomainSid.Value -cne $accountDomain) {
                $failures.Add("the account domain SID $accountDomain is not the local account's $($currentUser.User.AccountDomainSid.Value)")
            }
            $retiredLocal = $accountDomain + '-2147483000'
            if ((Get-TestSidUse $retiredLocal) -ne 0) {
                $failures.Add("the retired local SID $retiredLocal is mapped")
            }
            $retiredDeny = '(D;;0x1200a0;;;' + $retiredLocal + ')'
            Set-TestDirectorySddl $vendor ('O:BAG:BAD:P' + $retiredDeny + '(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)')
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor)) {
                $failures.Add('a deny entry for a retired account blocked the users check')
            }
            Set-TestDirectorySddl $vendor ('O:BAG:BAD:P' + $retiredDeny + '(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor)) {
                $failures.Add('the vendor grant did not converge beside a deny for a retired account')
            }
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(D;;0x1200a0;;;S-1-5-32-555)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)'
            if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                $failures.Add('a deny entry for a built-in group was not detected')
            }
            $self = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if (@(Get-DefenseClawManagedUserRuntimeHomes | Microsoft.PowerShell.Core\Where-Object { $_.sid -ceq $self }).Count -eq 1) {
                Set-TestDirectorySddl $vendor ('O:BAG:BAD:P(D;;0x1200a0;;;{0})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)' -f $self)
                if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                    $failures.Add('a deny entry for an enrolled user was not detected')
                }
            }
            # That deny names this account: drop it, so the scratch tree can
            # be listed and removed.
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'

            # Review of GAP-1158: the full standalone purge (the committed
            # cleanup's selector step, then the orphaned-state step) keeps a
            # selector that holds targets of this deployment and another,
            # with its lock and bytes. A selector with only this deployment's
            # targets goes, with or without a lock file, and neither step
            # touches a selector while a hook holds its lock.
            $ownHook = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe'
            $otherHook = 'D:\Other\DefenseClaw\bin\defenseclaw-hook.exe'
            $selectorPF = [IO.Path]::Combine($Root, 'selector-pf')
            $selectorPD = [IO.Path]::Combine($Root, 'selector-pd')
            $claudeDir = [IO.Path]::Combine($selectorPF, 'ClaudeCode', 'managed-settings.d')
            $codexDir = [IO.Path]::Combine($selectorPD, 'OpenAI', 'Codex')
            $cursorDir = [IO.Path]::Combine($selectorPD, 'Cursor')
            $stateLeaf = '.defenseclaw-managed-runtime-selector.state'
            $lockLeaf = '.defenseclaw-managed-runtime-selector.lock'
            function New-TestSelector([string]$Directory, [string[]]$Hooks) {
                [void][IO.Directory]::CreateDirectory($Directory)
                $targets = @(for ($i = 0; $i -lt $Hooks.Count; $i++) {
                        @{ connector = 'codex'; sid = "S-1-5-21-1-2-3-$(1001 + $i)"; hook_executable = $Hooks[$i] }
                    })
                $document = @{ schema_version = 1; connector = 'codex'; targets = $targets } |
                    Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4
                [IO.File]::WriteAllText([IO.Path]::Combine($Directory, $stateLeaf), $document)
                [IO.File]::WriteAllText([IO.Path]::Combine($Directory, $lockLeaf), '')
                # Setup writes these as an administrator. A runner account
                # whose token makes itself the owner of new files (the
                # built-in Administrator) would make them untrusted.
                foreach ($tree in @($selectorPF, $selectorPD)) {
                    if (-not [IO.Directory]::Exists($tree)) {
                        continue
                    }
                    foreach ($item in @(@(Microsoft.PowerShell.Management\Get-Item -LiteralPath $tree -Force) +
                            @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $tree -Recurse -Force))) {
                        $security = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $item.FullName
                        $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
                        Microsoft.PowerShell.Security\Set-Acl -LiteralPath $item.FullName -AclObject $security
                    }
                }
            }
            function Invoke-TestSelectorPurge {
                @(Remove-DefenseClawRuntimeSelectorState -HookPath $ownHook -Directories @($claudeDir, $codexDir, $cursorDir)) +
                @(Remove-DefenseClawStandaloneOrphanedHookMachineState `
                        -Layout @{ HookPath = $ownHook; CodexMachinePolicyDirectory = $codexDir } `
                        -ProgramFiles $selectorPF `
                        -ProgramData $selectorPD)
            }
            $codexState = [IO.Path]::Combine($codexDir, $stateLeaf)
            $codexLock = [IO.Path]::Combine($codexDir, $lockLeaf)
            $cursorState = [IO.Path]::Combine($cursorDir, $stateLeaf)
            $cursorLock = [IO.Path]::Combine($cursorDir, $lockLeaf)
            New-TestSelector $codexDir @($ownHook, $otherHook)
            $mixed = [IO.File]::ReadAllText($codexState)
            New-TestSelector $cursorDir @($ownHook)
            $left = @(Invoke-TestSelectorPurge)
            if (-not [IO.File]::Exists($codexState) -or -not [IO.File]::Exists($codexLock) -or
                [IO.File]::ReadAllText($codexState) -cne $mixed -or
                @($left | Microsoft.PowerShell.Core\Where-Object { $_ -like "*Codex*another DefenseClaw deployment*" }).Count -lt 1) {
                $failures.Add("the full purge removed or changed a selector shared with another deployment: $($left -join '; ')")
            }
            if ([IO.File]::Exists($cursorState) -or [IO.File]::Exists($cursorLock)) {
                $failures.Add("the full purge kept a selector with only this deployment's targets: $($left -join '; ')")
            }
            New-TestSelector $cursorDir @($ownHook)
            [IO.File]::Delete($cursorLock)
            $left = @(Invoke-TestSelectorPurge)
            if ([IO.File]::Exists($cursorState) -or [IO.File]::Exists($cursorLock)) {
                $failures.Add("a selector without a lock file stayed, or left a lock: $($left -join '; ')")
            }
            New-TestSelector $cursorDir @($ownHook)
            $script:RuntimeSelectorLockTimeoutSeconds = 1
            $hook = Start-TestHolder -Path $cursorLock -Mode Read -HoldMilliseconds 8000
            try {
                $left = @(Invoke-TestSelectorPurge)
                if (-not [IO.File]::Exists($cursorState) -or
                    @($left | Microsoft.PowerShell.Core\Where-Object { $_ -like "*Cursor*lock could not be taken*" }).Count -lt 1) {
                    $failures.Add("a selector was removed while a hook held its lock: $($left -join '; ')")
                }
            }
            finally {
                [void]$hook.WaitForExit(30000)
                $script:RuntimeSelectorLockTimeoutSeconds = $savedSelectorTimeout
            }
            $left = @(Invoke-TestSelectorPurge)
            if ([IO.File]::Exists($cursorState) -or [IO.File]::Exists($cursorLock)) {
                $failures.Add("the selector stayed after the hook released its lock: $($left -join '; ')")
            }

            # GAP-0152: the retained key held by the deleted gateway's
            # per-service SID becomes administrator-only with its bytes kept;
            # a key another account can read stays refused.
            $serviceName = 'DefenseClawW2BSmokeAbsent'
            $serviceSID = Get-DefenseClawDeterministicServiceSID -ServiceName $serviceName
            $runtime = [IO.Path]::Combine($Root, 'runtime')
            [void][IO.Directory]::CreateDirectory($runtime)
            $keyLayout = @{ RuntimeDirectory = $runtime; RedactionCorrelationKeyPath = [IO.Path]::Combine($runtime, 'redaction-correlation.key') }
            [IO.File]::WriteAllBytes($keyLayout.RedactionCorrelationKeyPath, [byte[]](1..32))
            $keyHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $keyLayout.RedactionCorrelationKeyPath).Hash
            function Set-TestKeySddl([string]$Sddl) {
                $security = [Security.AccessControl.FileSecurity]::new()
                $security.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]::All)
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $keyLayout.RedactionCorrelationKeyPath -AclObject $security
            }
            Set-TestKeySddl ('O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{0})' -f $serviceSID)
            Repair-DefenseClawRetainedRedactionKeyAcl -Layout $keyLayout -GatewayServiceName $serviceName
            try {
                $snapshot = Get-DefenseClawRedactionKeySecuritySnapshot -Layout $keyLayout -GatewayServiceSID ''
                if ([string]$snapshot.preimage_class -cne 'inactive_admin' -or
                    (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $keyLayout.RedactionCorrelationKeyPath).Hash -cne $keyHash) {
                    $failures.Add("the retained key was not normalized with its bytes kept: $($snapshot.preimage_class)")
                }
            }
            catch {
                $failures.Add("the retained service-held key is still refused: $($_.Exception.Message)")
            }
            Set-TestKeySddl ('O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{0})(A;;FR;;;BU)' -f $serviceSID)
            Repair-DefenseClawRetainedRedactionKeyAcl -Layout $keyLayout -GatewayServiceName $serviceName
            try {
                [void](Get-DefenseClawRedactionKeySecuritySnapshot -Layout $keyLayout -GatewayServiceSID '')
                $failures.Add('a key that Users can read was accepted')
            }
            catch {
                if ($_.Exception.Message -notlike '*Set-Acl*') {
                    $failures.Add("the refusal does not give the Set-Acl recovery: $($_.Exception.Message)")
                }
            }
        }
        finally {
            $script:ProgramData = $savedProgramData
            $script:InstallRootRetirementRetryMilliseconds = $savedRetry
            $script:RuntimeSelectorLockTimeoutSeconds = $savedSelectorTimeout
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $savedProfile
        }
        return , $failures
    } $root $modulePath
}
finally {
    foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Microsoft.PowerShell.Core\Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 })) {
        [IO.Directory]::Delete($entry.FullName)
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-w2b-lifecycle-smoke: OK'
