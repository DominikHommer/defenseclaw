# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Table test for the permission verdicts of Assert-DefenseClawPathAcl and the
# canonical-descriptor checks it relies on. A verdict for drift a standard user
# could have created (a write-like grant, a foreign owner, an unreadable
# descriptor) stays fatal after the canonical re-stamp on every profile, with
# and without DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS; only drift that
# needs an administrator (a read grant, a lost protected flag) may continue
# with a warning, and the strict pin restores those refusals too (GAP-0010).
# The verdict reader and the re-stamp are replaced inside the module, so the
# test touches no ACL on the machine.

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath -Force -PassThru -DisableNameChecking -ErrorAction Stop `
    -WarningAction SilentlyContinue

$strictEnv = 'DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS'
$savedStrict = [Environment]::GetEnvironmentVariable($strictEnv, 'Process')
$fixture = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(),
    'dc-path-acl-verdict-' + [Guid]::NewGuid().ToString('N') + '.bin'
)
[IO.File]::WriteAllBytes($fixture, [byte[]]@(0))

$write = @{ Kind = 'Access'; Severity = 'Write'; Reason = 'untrusted principal S-1-5-21-1-2-3-1001 has write-like access to managed path: x' }
$read = @{ Kind = 'Access'; Severity = 'Read'; Reason = 'untrusted principal S-1-5-21-1-2-3-1001 can read protected managed path: x' }
$inherit = @{ Kind = 'Access'; Severity = 'Inheritance'; Reason = 'managed DACL inherits from an ancestor: x' }
$owner = @{ Kind = 'Contract'; Reason = 'untrusted owner S-1-5-21-1-2-3-1001 on managed path: x' }
$rights = @{ Kind = 'Rights'; Reason = 'managed path is missing required rights for S-1-5-18: x' }

# before = first reading, after = reading after the re-stamp, stamp = what the
# re-stamp does, heal = -SelfHealKind given, advisory = -AdvisoryUntrustedAccess.
$cases = @(
    @{ name = 'write survives a re-stamp that does nothing'; before = @($write); after = @($write); stamp = 'noop'; strict = ''; expect = $write.Reason }
    @{ name = 'write survives a re-stamp that fails'; before = @($write); after = @($write); stamp = 'throw'; strict = ''; expect = $write.Reason }
    @{ name = 'write survives, strict pin'; before = @($write); after = @($write); stamp = 'noop'; strict = '1'; expect = $write.Reason }
    @{ name = 'write cleared by the re-stamp'; before = @($write); after = @(); stamp = 'noop'; strict = ''; expect = '' }
    @{ name = 'write behind a read keeps the write message'; before = @($read, $write); after = @($read, $write); stamp = 'noop'; strict = ''; expect = $write.Reason }
    @{ name = 'write without a self-heal'; before = @($write); after = $null; heal = $false; strict = ''; expect = $write.Reason }
    @{ name = 'read survives'; before = @($read); after = @($read); stamp = 'noop'; strict = ''; expect = '' }
    @{ name = 'read survives, strict pin'; before = @($read); after = @($read); stamp = 'noop'; strict = '1'; expect = $read.Reason }
    @{ name = 'lost protected flag survives the re-stamp'; before = @($inherit); after = @($inherit); stamp = 'throw'; strict = ''; expect = '' }
    @{ name = 'lost protected flag survives, strict pin'; before = @($inherit); after = @($inherit); stamp = 'noop'; strict = '1'; expect = $inherit.Reason }
    @{ name = 'lost protected flag without a self-heal'; before = @($inherit); after = $null; heal = $false; strict = ''; expect = $inherit.Reason }
    @{ name = 'foreign owner survives'; before = @($owner); after = @($owner); stamp = 'noop'; strict = ''; expect = $owner.Reason }
    @{ name = 'missing rights survive'; before = @($rights); after = @($rights); stamp = 'noop'; strict = ''; expect = $rights.Reason }
    @{ name = 'Secure Client state root advisory'; before = @($write); after = @($write); stamp = 'noop'; strict = ''; advisory = $true; profile = 'SecureClient'; expect = '' }
    @{ name = 'Secure Client state root advisory, strict pin'; before = @($write); after = @($write); stamp = 'noop'; strict = '1'; advisory = $true; profile = 'SecureClient'; expect = $write.Reason }
)

$failures = [Collections.Generic.List[string]]::new()
try {
    foreach ($case in $cases) {
        [Environment]::SetEnvironmentVariable($strictEnv, [string]$case.strict, 'Process')
        $heal = -not $case.ContainsKey('heal') -or [bool]$case.heal
        $advisory = $case.ContainsKey('advisory') -and [bool]$case.advisory
        $profileName = if ($case.ContainsKey('profile')) { [string]$case.profile } else { 'Standalone' }
        $observed = & $module {
            param($Case, $Fixture, $Heal, $Advisory, $ProfileName)
            $script:DefenseClawEnterpriseProfile = $ProfileName
            $script:VerdictReadings = [Collections.Generic.List[object]]::new()
            foreach ($reading in @($Case['before'], $Case['after'])) {
                $script:VerdictReadings.Add([object[]]@(
                    $reading | Microsoft.PowerShell.Core\ForEach-Object { [pscustomobject]$_ }
                ))
            }
            $script:VerdictReads = 0
            $script:StampMode = [string]$Case['stamp']
            function script:Get-DefenseClawPathAclVerdicts {
                $reading = $script:VerdictReadings[[Math]::Min($script:VerdictReads, 1)]
                $script:VerdictReads++
                return $reading
            }
            function script:Set-DefenseClawPathAcl {
                if ($script:StampMode -ceq 'throw') { throw 'simulated: the canonical stamp lost a race' }
            }
            $arguments = @{
                Path              = $Fixture
                AllowedWriterSIDs = @($script:SystemSID, $script:AdministratorsSID)
                AllowUsersRead    = $true
            }
            if ($Heal) {
                $arguments['SelfHealKind'] = 'ServiceInstallFile'
                $arguments['SelfHealGatewayServiceSID'] = 'S-1-5-80-1'
            }
            if ($Advisory) {
                $arguments['AdvisoryUntrustedAccess'] = $true
            }
            try {
                Assert-DefenseClawPathAcl @arguments -WarningAction SilentlyContinue
                return ''
            }
            catch {
                return [string]$_.Exception.Message
            }
        } $case $fixture $heal $advisory $profileName
        if ([string]$observed -cne [string]$case.expect) {
            $want = if ($case.expect) { "refusal '$($case.expect)'" } else { 'pass' }
            $failures.Add("$($case.name): want $want, got '$observed'")
        }
    }
}
finally {
    [Environment]::SetEnvironmentVariable($strictEnv, $savedStrict, 'Process')
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Core\Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
}
if ($failures.Count -gt 0) {
    throw ("enterprise-path-acl-verdict-smoke: FAIL`n" + ($failures -join "`n"))
}
Microsoft.PowerShell.Utility\Write-Host "enterprise-path-acl-verdict-smoke: PASS ($($cases.Count) cases)"
