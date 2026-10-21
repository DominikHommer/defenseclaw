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
