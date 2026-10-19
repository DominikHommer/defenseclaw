# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'

# The Secure Client uninstall with purge (Invoke-DefenseClawNuclearUninstall)
# runs elevated. It must never follow a link or junction: not at a root, not
# below one, and not in a folder above one (GAP-0011). It must refuse while a
# standalone deployment is installed and leave the services and machine
# policy another profile owns as found (GAP-0012), and it must change an
# agent's machine policy only as DefenseClaw's ownership records allow
# (GAP-0017). The standalone forced uninstall (Setup /uninstall FORCE=1)
# puts the administrator's Codex requirements.toml back from the ownership
# record in the StateRoot it moved aside, by the same rules, before that
# folder goes, and keeps the folder when it cannot (GAP-0028). The functions run from
# the real module against throwaway ProgramFiles and ProgramData folders;
# native helpers and service control are stand-ins, so the run needs neither
# elevation nor a DefenseClaw install. Junctions need Windows.
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Microsoft.PowerShell.Utility\Write-Output 'SKIP enterprise-nuclear-purge-smoke: junctions need Windows'
    return
}

$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$tokens = $null
$parseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "module parser errors: $($parseErrors.Message -join '; ')"
}
foreach ($name in @(
    'Get-DefenseClawProfileRoots',
    'Get-DefenseClawNuclearSafeRootPattern',
    'Test-DefenseClawPathPresentNoFollow',
    'Remove-DefenseClawNoFollowTree',
    'Assert-DefenseClawNuclearPathNoLink',
    'Reset-DefenseClawNuclearEntryAccess',
    'Remove-DefenseClawNuclearPath',
    'Test-DefenseClawNuclearPathWithin',
    'Get-DefenseClawNuclearSHA256',
    'Read-DefenseClawNuclearFileBytes',
    'Read-DefenseClawNuclearRecord',
    'Get-DefenseClawNuclearRecordField',
    'Write-DefenseClawNuclearFileContent',
    'Get-DefenseClawNuclearConnectorOwner',
    'Test-DefenseClawNuclearDropInOwned',
    'Test-DefenseClawNuclearCursorHooksOwnedOnly',
    'Invoke-DefenseClawNuclearCodexRequirements',
    'Restore-DefenseClawForcedUninstallCodexPolicy',
    'Complete-DefenseClawForcedUninstall',
    'Invoke-DefenseClawNuclearCursorHooks',
    'Invoke-DefenseClawNuclearAgentPolicy',
    'Invoke-DefenseClawNuclearUninstall',
    'Invoke-DefenseClawNuclearUninstallRoute',
    'Test-DefenseClawStandaloneProfile',
    'Test-DefenseClawTrustStrictAncestors',
    'Test-DefenseClawMetadataInstalled',
    'Test-DefenseClawProfileDeploymentInstalled',
    'Assert-DefenseClawNoOtherProfileDeployment'
)) {
    $functionAst = @($moduleAst.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
        },
        $true
    ))
    if ($functionAst.Count -ne 1) {
        throw "expected exactly one $name in the module"
    }
    . ([scriptblock]::Create($functionAst[0].Extent.Text))
}

# The native folder pin opens without following and refuses a link; this
# stand-in refuses the same way so the walk runs unelevated.
if (-not ('DefenseClawNuclearPurgeSmokePin' -as [type])) {
    Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @"
public static class DefenseClawNuclearPurgeSmokePin {
    public static System.IntPtr OpenDirectoryPinNoFollow(string path) {
        var attributes = System.IO.File.GetAttributes(path);
        if ((attributes & System.IO.FileAttributes.ReparsePoint) != 0 ||
            (attributes & System.IO.FileAttributes.Directory) == 0)
            throw new System.InvalidOperationException("refusing a link, junction or non-folder: " + path);
        return new System.IntPtr(1);
    }
    public static void CloseDirectoryPin(System.IntPtr handle) {}
}
"@
}
function Initialize-DefenseClawNativeSecurity { return [DefenseClawNuclearPurgeSmokePin] }
$script:execCalls = [Collections.Generic.List[string]]::new()
function Invoke-DefenseClawNuclearSilentExec {
    param([string]$File, [string[]]$Arguments = @())
    $script:execCalls.Add(([IO.Path]::GetFileName($File) + ' ' + ($Arguments -join ' ')))
}
$script:trustedOwner = $true
function Test-DefenseClawNuclearTrustedOwner {
    param([string]$Path)
    return $script:trustedOwner
}
function Get-DefenseClawEnumeratorServiceName { param([string]$GuardianServiceName) return 'DefenseClawSmokeEnumerator_0000000000' }
function Get-DefenseClawCMIDBrokerServiceName { param([string]$GatewayServiceName) return 'DefenseClawSmokeBroker_0000000000' }
function Get-DefenseClawSensorHelperServiceName { param([string]$GatewayServiceName) return 'DefenseClawSmokeSensor_0000000000' }
$script:userRuntimeCalls = 0
function Remove-DefenseClawManagedUserRuntimeLeftovers {
    $script:userRuntimeCalls++
    return [pscustomobject]@{ removed = [string[]]@(); remaining = [string[]]@() }
}
# Service rows by name: the executable their ImagePath starts.
$script:serviceImages = @{}
function Get-DefenseClawNuclearServiceImage {
    param([string]$Name)
    if ($script:serviceImages.ContainsKey($Name)) {
        return [string]$script:serviceImages[$Name]
    }
    return $null
}
$script:stoppedServices = $null
function Stop-DefenseClawNuclearServices {
    param([string[]]$Names, [string]$InstallRoot, $Warnings)
    $script:stoppedServices = @($Names)
}
# Records listed here fail the access check, as one a standard user can
# write does.
$script:untrustedRecords = @()
function Assert-DefenseClawNuclearRecordTrusted {
    param([string]$Path)
    if ($Path -in $script:untrustedRecords) {
        throw "$Path is writable by BUILTIN\Users"
    }
}
function Test-DefenseClawAdministrator { return $false }
$script:removedTrees = [Collections.Generic.List[string]]::new()
function Remove-DefenseClawManagedTree {
    param([string]$Path, [string]$RequiredBase, [string]$Label)
    $script:removedTrees.Add($Path)
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Path -Recurse -Force
}
function ConvertTo-DefenseClawBoundedDiagnostic {
    param($Value, [int]$MaxLength = 512)
    return (@($Value) -join ' ')
}
function Test-DefenseClawServiceExists { param([string]$Name) return $false }

$script:tmp = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        ([IO.Path]::GetTempPath()) `
        ('dc-nuclear-smoke-' + [Guid]::NewGuid().ToString('N'))
))
$script:ProgramFiles = [IO.Path]::Combine($script:tmp, 'PF')
$script:ProgramData = [IO.Path]::Combine($script:tmp, 'PD')
$script:System32 = [IO.Path]::Combine($env:windir, 'System32')
$script:ScExe = [IO.Path]::Combine($script:System32, 'sc.exe')
$script:IcaclsExe = [IO.Path]::Combine($script:System32, 'icacls.exe')
$script:NuclearUninstallMarker = 'managed_nuclear_uninstall'
$script:SystemSID = 'S-1-5-18'
$script:AdministratorsSID = 'S-1-5-32-544'
$script:TrustedInstallerSID = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:DefenseClawEnterpriseProfile = 'SecureClient'
$script:TrustStrictAncestorsEnv = 'DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS'
[Environment]::SetEnvironmentVariable($script:TrustStrictAncestorsEnv, $null, 'Process')
$script:junctions = [Collections.Generic.List[string]]::new()
$script:roots = Get-DefenseClawProfileRoots -EnterpriseProfile SecureClient

function New-SmokeFile {
    param([string]$Path, [string]$Text = 'x')
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    [IO.File]::WriteAllText($Path, $Text)
}
function New-SmokeJunction {
    param([string]$Path, [string]$Target)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    [void][IO.Directory]::CreateDirectory($Target)
    [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $Path -Target $Target)
    $script:junctions.Add($Path)
}
function Reset-SmokeTree {
    # Links go first, as links only, so the cleanup never reaches through one.
    foreach ($junction in @($script:junctions)) {
        if ([IO.Directory]::Exists($junction) -or
            (Test-DefenseClawPathPresentNoFollow -Path $junction)) {
            [IO.Directory]::Delete($junction, $false)
        }
    }
    $script:junctions.Clear()
    if ([IO.Directory]::Exists($script:tmp)) {
        Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $script:tmp -Recurse -Force |
            Microsoft.PowerShell.Core\ForEach-Object { $_.Attributes = [IO.FileAttributes]::Normal }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $script:tmp -Recurse -Force
    }
    [void][IO.Directory]::CreateDirectory($script:tmp)
    $script:execCalls.Clear()
    $script:trustedOwner = $true
    $script:userRuntimeCalls = 0
    $script:serviceImages = @{}
    $script:stoppedServices = $null
    $script:untrustedRecords = @()
    $script:DefenseClawEnterpriseProfile = 'SecureClient'
}
function Write-SmokeJson {
    param([string]$Path, $Value)
    New-SmokeFile -Path $Path -Text ($Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress)
}
function Get-SmokeBytes {
    param([string]$Path)
    return ,[IO.File]::ReadAllBytes($Path)
}
function Test-SmokeSameBytes {
    param([string]$Path, [byte[]]$Expected)
    if (-not [IO.File]::Exists($Path)) {
        return $false
    }
    return (Get-DefenseClawNuclearSHA256 -Bytes (Get-SmokeBytes -Path $Path)) -ceq (Get-DefenseClawNuclearSHA256 -Bytes $Expected)
}
function Invoke-SmokeRoute {
    return Invoke-DefenseClawNuclearUninstallRoute `
        -Action Uninstall `
        -Purge $true `
        -InstallRoot ([string]$script:roots.InstallRoot) `
        -StateRoot ([string]$script:roots.StateRoot) `
        -GatewayServiceName 'DefenseClawSmokeGateway_0000000000' `
        -GuardianServiceName 'DefenseClawSmokeGuardian_0000000000'
}
function Invoke-SmokeNuclear {
    return Invoke-DefenseClawNuclearUninstall `
        -Layout @{
            InstallRoot = [string]$script:roots.InstallRoot
            StateRoot = [string]$script:roots.StateRoot
        } `
        -GatewayServiceName 'DefenseClawSmokeGateway_0000000000' `
        -GuardianServiceName 'DefenseClawSmokeGuardian_0000000000'
}
function Assert-Smoke {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "nuclear purge smoke: $Message"
    }
}
function Assert-SmokeNoAccessReset {
    param([string]$Case)
    $resets = @($script:execCalls | Microsoft.PowerShell.Core\Where-Object {
        $_ -like 'takeown.exe*' -or $_ -like 'icacls.exe*'
    })
    Assert-Smoke ($resets.Count -eq 0) "${Case}: unexpected ownership or access reset: $($resets -join '; ')"
}

try {
    # Path checks, read without following any component.
    Reset-SmokeTree
    $real = [IO.Path]::Combine($script:tmp, 'real', 'child')
    [void][IO.Directory]::CreateDirectory($real)
    $linkParent = [IO.Path]::Combine($script:tmp, 'linked')
    New-SmokeJunction -Path $linkParent -Target ([IO.Path]::Combine($script:tmp, 'real'))
    $dangling = [IO.Path]::Combine($script:tmp, 'dangling')
    New-SmokeJunction -Path $dangling -Target ([IO.Path]::Combine($script:tmp, 'gone'))
    [IO.Directory]::Delete([IO.Path]::Combine($script:tmp, 'gone'), $false)
    foreach ($case in @(
        @{ Path = $real; Refused = $false },
        @{ Path = [IO.Path]::Combine($script:tmp, 'missing', 'leaf'); Refused = $false },
        @{ Path = [IO.Path]::Combine($linkParent, 'child'); Refused = $true },
        @{ Path = $linkParent; Refused = $true },
        @{ Path = $dangling; Refused = $true },
        @{ Path = [IO.Path]::Combine($dangling, 'below'); Refused = $true }
    )) {
        $refused = $false
        try {
            Assert-DefenseClawNuclearPathNoLink -Path $case.Path
        }
        catch {
            $refused = $true
        }
        Assert-Smoke ($refused -eq $case.Refused) "path check for $($case.Path): refused=$refused, want $($case.Refused)"
    }

    # A user-made junction where a missing root would be (StateRoot and the
    # lifecycle folder), and one below InstallRoot: the protected folder they
    # name keeps its content, the links stay, and nothing gets an ownership or
    # access reset. The real InstallRoot tree goes.
    Reset-SmokeTree
    $protected = [IO.Path]::Combine($script:tmp, 'protected')
    New-SmokeFile -Path ([IO.Path]::Combine($protected, 'keep.txt'))
    New-SmokeJunction -Path ([string]$script:roots.StateRoot) -Target $protected
    New-SmokeJunction -Path ([string]$script:roots.LifecycleDirectory) -Target $protected
    $installRoot = [string]$script:roots.InstallRoot
    New-SmokeFile -Path ([IO.Path]::Combine($installRoot, 'bin', 'defenseclaw-gateway.exe'))
    New-SmokeFile -Path ([IO.Path]::Combine($installRoot, 'etc', 'deep', 'config.yaml'))
    [IO.File]::SetAttributes(
        [IO.Path]::Combine($installRoot, 'etc', 'deep', 'config.yaml'),
        [IO.FileAttributes]::ReadOnly
    )
    $result = Invoke-SmokeNuclear
    Assert-Smoke ([IO.File]::Exists([IO.Path]::Combine($protected, 'keep.txt'))) 'a junction at a root redirected the purge'
    Assert-Smoke (Test-DefenseClawPathPresentNoFollow -Path ([string]$script:roots.StateRoot)) 'the StateRoot junction was not left as found'
    Assert-Smoke (-not (Test-DefenseClawPathPresentNoFollow -Path $installRoot)) 'the real InstallRoot tree was not removed'
    Assert-SmokeNoAccessReset -Case 'junction at a root'
    Assert-Smoke (@($result.warnings | Microsoft.PowerShell.Core\Where-Object { $_ -like '*reparse points are not allowed*' }).Count -ge 2) 'the left links are not named in warnings'

    Reset-SmokeTree
    New-SmokeFile -Path ([IO.Path]::Combine($protected, 'keep.txt'))
    New-SmokeFile -Path ([IO.Path]::Combine($installRoot, 'bin', 'defenseclaw-gateway.exe'))
    New-SmokeJunction -Path ([IO.Path]::Combine($installRoot, 'bin', 'link')) -Target $protected
    $result = Invoke-SmokeNuclear
    Assert-Smoke ([IO.File]::Exists([IO.Path]::Combine($protected, 'keep.txt'))) 'a junction below a root redirected the purge'
    Assert-Smoke (-not [IO.File]::Exists([IO.Path]::Combine($installRoot, 'bin', 'defenseclaw-gateway.exe'))) 'files beside a junction were not removed'
    Assert-SmokeNoAccessReset -Case 'junction below a root'
    Assert-Smoke (@($result.warnings | Microsoft.PowerShell.Core\Where-Object { $_ -like '*a link or junction; left as found*' }).Count -ge 1) 'the link below a root is not named in warnings'

    # A junction in a folder above the roots and above an agent policy
    # folder: nothing in the folders they name is touched.
    Reset-SmokeTree
    $elsewhere = [IO.Path]::Combine($script:tmp, 'elsewhere')
    New-SmokeFile -Path ([IO.Path]::Combine($elsewhere, 'Cisco Secure Client', 'DefenseClaw', 'keep.txt'))
    New-SmokeJunction -Path ([IO.Path]::Combine($script:ProgramData, 'Cisco')) -Target $elsewhere
    $agentElsewhere = [IO.Path]::Combine($script:tmp, 'agent-elsewhere')
    New-SmokeFile -Path ([IO.Path]::Combine($agentElsewhere, 'Codex', '.defenseclaw-managed-hooks.state'))
    New-SmokeJunction -Path ([IO.Path]::Combine($script:ProgramData, 'OpenAI')) -Target $agentElsewhere
    $result = Invoke-SmokeNuclear
    Assert-Smoke ([IO.File]::Exists([IO.Path]::Combine($elsewhere, 'Cisco Secure Client', 'DefenseClaw', 'keep.txt'))) 'a junction above StateRoot redirected the purge'
    Assert-Smoke ([IO.File]::Exists([IO.Path]::Combine($agentElsewhere, 'Codex', '.defenseclaw-managed-hooks.state'))) 'a junction above the Codex policy folder redirected the purge'
    Assert-SmokeNoAccessReset -Case 'junction above a root'
    Assert-Smoke (@($result.warnings | Microsoft.PowerShell.Core\Where-Object { $_ -like '*reparse points are not allowed*' }).Count -ge 2) 'the refused ancestors are not named in warnings'

    # GAP-0012: the route refuses while a standalone deployment is installed,
    # before anything is removed; a tombstone does not block; the standalone
    # profile and strict mode never take the Secure Client hammer.
    Reset-SmokeTree
    $standaloneRoots = Get-DefenseClawProfileRoots -EnterpriseProfile Standalone
    $standaloneRecord = [IO.Path]::Combine([string]$standaloneRoots.StateRoot, 'install', 'deployment.json')
    Write-SmokeJson -Path $standaloneRecord -Value @{ schema_version = 1; installed = $true }
    $scMarker = [IO.Path]::Combine([string]$script:roots.InstallRoot, 'bin', 'defenseclaw-gateway.exe')
    New-SmokeFile -Path $scMarker
    $refusal = ''
    try {
        [void](Invoke-SmokeRoute)
    }
    catch {
        $refusal = $_.Exception.Message
    }
    Assert-Smoke ($refusal -like 'profile_conflict:*') "an installed standalone deployment did not refuse the purge: '$refusal'"
    Assert-Smoke ([IO.File]::Exists($scMarker) -and $null -eq $script:stoppedServices) 'the refused purge removed something'
    Write-SmokeJson -Path $standaloneRecord -Value @{ schema_version = 1; installed = $false }
    $result = Invoke-SmokeRoute
    Assert-Smoke ($null -ne $result -and [bool]$result.nuclear -and -not [IO.File]::Exists($scMarker)) 'an uninstall tombstone blocked the purge'
    $script:DefenseClawEnterpriseProfile = 'Standalone'
    Assert-Smoke ($null -eq (Invoke-SmokeRoute)) 'the standalone profile took the Secure Client purge'
    $script:DefenseClawEnterpriseProfile = 'SecureClient'
    [Environment]::SetEnvironmentVariable($script:TrustStrictAncestorsEnv, '1', 'Process')
    try {
        Assert-Smoke ($null -eq (Invoke-SmokeRoute)) 'strict mode took the nuclear purge'
    }
    finally {
        [Environment]::SetEnvironmentVariable($script:TrustStrictAncestorsEnv, $null, 'Process')
    }

    # GAP-0012: the shared service names run the standalone deployment (no
    # record says so): those services, the agents' machine policy and the
    # accounts' runtime stay; only the service from this InstallRoot goes.
    Reset-SmokeTree
    $standaloneBin = [IO.Path]::Combine([string]$standaloneRoots.InstallRoot, 'bin')
    $script:serviceImages = @{
        'DefenseClawSmokeGateway_0000000000' = [IO.Path]::Combine($standaloneBin, 'defenseclaw-gateway.exe')
        'DefenseClawSmokeGuardian_0000000000' = [IO.Path]::Combine($standaloneBin, 'defenseclaw-gateway.exe')
        'DefenseClawSmokeBroker_0000000000' = [IO.Path]::Combine([string]$script:roots.InstallRoot, 'bin', 'defenseclaw-cmid-broker.exe')
    }
    $claudeDir = [IO.Path]::Combine($script:ProgramFiles, 'ClaudeCode', 'managed-settings.d')
    $standaloneHook = [IO.Path]::Combine($standaloneBin, 'defenseclaw-hook.exe')
    $claudePolicy = [IO.Path]::Combine($claudeDir, '90-defenseclaw.json')
    Write-SmokeJson -Path $claudePolicy -Value @{ hooks = @{ PreToolUse = @(@{ command = $standaloneHook }) } }
    Write-SmokeJson -Path ([IO.Path]::Combine($claudeDir, '.defenseclaw-managed-hooks.state')) -Value @{ schema_version = 1; hook_executable = $standaloneHook }
    $codexPolicy = [IO.Path]::Combine($script:ProgramData, 'OpenAI', 'Codex', 'requirements.toml')
    New-SmokeFile -Path $codexPolicy -Text "allowed_sandbox_modes = [`"read-only`"]`n"
    $result = Invoke-SmokeNuclear
    Assert-Smoke ((@($script:stoppedServices) -join ',') -ceq 'DefenseClawSmokeBroker_0000000000') "services torn down: $(@($script:stoppedServices) -join ',')"
    Assert-Smoke (@($result.warnings | Microsoft.PowerShell.Core\Where-Object { $_ -like '*left service DefenseClawSmokeGateway_0000000000 as found*' }).Count -eq 1) 'the standalone gateway service is not named as left'
    Assert-Smoke ([IO.File]::Exists($claudePolicy) -and [IO.File]::Exists($codexPolicy)) 'the standalone deployment''s machine policy was removed'
    Assert-Smoke ($script:userRuntimeCalls -eq 0) 'the accounts'' runtime was cleaned while another deployment runs'

    # GAP-0017: an administrator's Codex and Cursor policy with no DefenseClaw
    # record stays byte for byte, and so do the records beside a kept file.
    Reset-SmokeTree
    $codexDir = [IO.Path]::Combine($script:ProgramData, 'OpenAI', 'Codex')
    $cursorDir = [IO.Path]::Combine($script:ProgramData, 'Cursor')
    $adminCodex = [Text.Encoding]::UTF8.GetBytes("approval_policy = `"never`"`n")
    New-SmokeFile -Path $codexPolicy -Text ([Text.Encoding]::UTF8.GetString($adminCodex))
    $codexLock = [IO.Path]::Combine($codexDir, '.defenseclaw-managed-hooks.lock')
    New-SmokeFile -Path $codexLock
    $cursorHooks = [IO.Path]::Combine($cursorDir, 'hooks.json')
    $adminCursor = [Text.Encoding]::UTF8.GetBytes('{"version":1,"hooks":{"beforeShellExecution":[{"command":"C:\\Tools\\audit.exe"}]}}')
    New-SmokeFile -Path $cursorHooks -Text ([Text.Encoding]::UTF8.GetString($adminCursor))
    $result = Invoke-SmokeNuclear
    Assert-Smoke (Test-SmokeSameBytes -Path $codexPolicy -Expected $adminCodex) 'an administrator''s Codex requirements.toml was changed'
    Assert-Smoke (Test-SmokeSameBytes -Path $cursorHooks -Expected $adminCursor) 'an administrator''s Cursor hooks.json was changed'
    Assert-Smoke ([IO.File]::Exists($codexLock)) 'the records beside a kept Codex policy were removed'
    Assert-SmokeNoAccessReset -Case 'administrator policy'
    Assert-Smoke ($script:userRuntimeCalls -eq 1) 'the accounts'' runtime was not cleaned'

    # GAP-0017: what this deployment provably wrote goes. Codex gets the
    # administrator's preimage back, a Cursor hooks.json DefenseClaw created
    # with only its hooks is removed, and so is a Claude drop-in for this
    # InstallRoot; the agents' DefenseClaw records go with them.
    Reset-SmokeTree
    $scHook = [IO.Path]::Combine([string]$script:roots.InstallRoot, 'bin', 'defenseclaw-hook.exe')
    $postimage = [Text.Encoding]::UTF8.GetBytes("approval_policy = `"never`"`n[hooks]`nmanaged = true`n")
    New-SmokeFile -Path $codexPolicy -Text ([Text.Encoding]::UTF8.GetString($postimage))
    $codexState = [IO.Path]::Combine($codexDir, '.defenseclaw-managed-hooks.state')
    Write-SmokeJson -Path $codexState -Value @{ schema_version = 1; hook_executable = $scHook }
    $ownershipPath = [IO.Path]::Combine([string]$script:roots.StateRoot, 'install', 'codex-requirements-ownership.json')
    $ownership = [ordered]@{
        schema_version = 1
        requirements_path = $codexPolicy
        hook_binary = $scHook
        preimage_existed = $true
        preimage = [Convert]::ToBase64String($adminCodex)
        preimage_sha256 = (Get-DefenseClawNuclearSHA256 -Bytes $adminCodex)
        postimage_sha256 = (Get-DefenseClawNuclearSHA256 -Bytes $postimage)
    }
    Write-SmokeJson -Path $ownershipPath -Value $ownership
    $adapter = [IO.Path]::Combine($cursorDir, 'defenseclaw-hook.ps1')
    New-SmokeFile -Path $adapter -Text '# adapter'
    $wrapper = '$payload=[Console]::In.ReadToEnd();$payload | & ''' + $adapter + ''''
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapper))
    $ownedCursor = @{
        version = 1
        hooks = @{
            beforeShellExecution = @(@{ command = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded" })
            beforeMCPExecution = @(@{ command = "& '$adapter'" })
        }
    }
    Write-SmokeJson -Path $cursorHooks -Value $ownedCursor
    $cursorReceipt = [IO.Path]::Combine($cursorDir, '.defenseclaw-managed-hooks.receipt')
    Write-SmokeJson -Path $cursorReceipt -Value @{ schema_version = 1; config_preexisting = $false }
    $cursorState = [IO.Path]::Combine($cursorDir, '.defenseclaw-managed-hooks.state')
    Write-SmokeJson -Path $cursorState -Value @{
        schema_version = 1
        hook_executable = $scHook
        receipt_sha256 = 'sha256:' + (Get-DefenseClawNuclearSHA256 -Bytes (Get-SmokeBytes -Path $cursorReceipt))
    }
    Write-SmokeJson -Path $claudePolicy -Value @{ hooks = @{ PreToolUse = @(@{ command = $scHook }) } }
    $claudeState = [IO.Path]::Combine($claudeDir, '.defenseclaw-managed-hooks.state')
    Write-SmokeJson -Path $claudeState -Value @{ schema_version = 1; hook_executable = $scHook }
    $result = Invoke-SmokeNuclear
    Assert-Smoke (Test-SmokeSameBytes -Path $codexPolicy -Expected $adminCodex) "the administrator's Codex preimage was not restored: $($result.warnings -join ' | ')"
    Assert-Smoke (-not [IO.File]::Exists($codexState)) 'the Codex ownership state of a restored policy stayed'
    foreach ($gone in @($cursorHooks, $adapter, $cursorReceipt, $cursorState, $claudePolicy, $claudeState)) {
        Assert-Smoke (-not [IO.File]::Exists($gone)) "$gone stayed: $($result.warnings -join ' | ')"
    }

    # GAP-0017: a Codex policy changed after DefenseClaw wrote it, a Cursor
    # hooks.json the administrator had before, and a Codex state a standard
    # user could write all stay, with their records.
    Reset-SmokeTree
    New-SmokeFile -Path $codexPolicy -Text "approval_policy = `"on-request`"`n"
    $edited = Get-SmokeBytes -Path $codexPolicy
    Write-SmokeJson -Path $ownershipPath -Value $ownership
    Write-SmokeJson -Path $cursorHooks -Value $ownedCursor
    $kept = Get-SmokeBytes -Path $cursorHooks
    Write-SmokeJson -Path $cursorReceipt -Value @{ schema_version = 1; config_preexisting = $true }
    Write-SmokeJson -Path $cursorState -Value @{
        schema_version = 1
        hook_executable = $scHook
        receipt_sha256 = 'sha256:' + (Get-DefenseClawNuclearSHA256 -Bytes (Get-SmokeBytes -Path $cursorReceipt))
    }
    $result = Invoke-SmokeNuclear
    Assert-Smoke (Test-SmokeSameBytes -Path $codexPolicy -Expected $edited) 'a Codex policy edited after install was changed'
    Assert-Smoke (Test-SmokeSameBytes -Path $cursorHooks -Expected $kept) 'a Cursor hooks.json that predates DefenseClaw was changed'
    Assert-Smoke ([IO.File]::Exists($cursorReceipt) -and [IO.File]::Exists($cursorState)) 'the Cursor records beside a kept hooks.json were removed'
    Reset-SmokeTree
    Write-SmokeJson -Path $cursorHooks -Value $ownedCursor
    Write-SmokeJson -Path $cursorReceipt -Value @{ schema_version = 1; config_preexisting = $false }
    Write-SmokeJson -Path $cursorState -Value @{
        schema_version = 1
        hook_executable = $scHook
        receipt_sha256 = 'sha256:' + (Get-DefenseClawNuclearSHA256 -Bytes (Get-SmokeBytes -Path $cursorReceipt))
    }
    $script:untrustedRecords = @($cursorState)
    $result = Invoke-SmokeNuclear
    Assert-Smoke ([IO.File]::Exists($cursorHooks) -and [IO.File]::Exists($cursorState)) 'an untrusted Cursor state decided the purge'

    # A Codex policy DefenseClaw created, unchanged since, is removed.
    Reset-SmokeTree
    New-SmokeFile -Path $codexPolicy -Text ([Text.Encoding]::UTF8.GetString($postimage))
    $created = [ordered]@{}
    foreach ($key in $ownership.Keys) { $created[$key] = $ownership[$key] }
    $created.preimage_existed = $false
    $created.Remove('preimage')
    Write-SmokeJson -Path $ownershipPath -Value $created
    $result = Invoke-SmokeNuclear
    Assert-Smoke (-not [IO.File]::Exists($codexPolicy)) "a Codex policy DefenseClaw created stayed: $($result.warnings -join ' | ')"

    # GAP-0028: a standalone forced uninstall. The managed-hook teardown did
    # not run, so requirements.toml is still DefenseClaw's postimage for the
    # standalone hook, and the administrator's original is only in the
    # ownership record in the StateRoot the preparation moved aside.
    $standaloneRoot = [IO.Path]::Combine($script:ProgramFiles, 'Cisco', 'DefenseClaw')
    $standaloneHook = [IO.Path]::Combine($standaloneRoot, 'bin', 'defenseclaw-hook.exe')
    $standaloneState = [IO.Path]::Combine($script:ProgramData, 'Cisco', 'DefenseClaw')
    $forcedLayout = @{ InstallRoot = $standaloneRoot; StateRoot = $standaloneState }
    $moved = $standaloneState + '.forced-uninstall-20261019T000000Z'
    $movedOwnership = [IO.Path]::Combine($moved, 'install', 'codex-requirements-ownership.json')
    $codexLockPath = [IO.Path]::Combine($codexDir, '.defenseclaw-managed-hooks.lock')
    $forcedOwnership = [ordered]@{}
    foreach ($key in $ownership.Keys) { $forcedOwnership[$key] = $ownership[$key] }
    $forcedOwnership.hook_binary = $standaloneHook
    $newForcedCase = {
        param([byte[]]$Policy)
        Reset-SmokeTree
        $script:removedTrees.Clear()
        New-SmokeFile -Path $codexPolicy -Text ([Text.Encoding]::UTF8.GetString($Policy))
        Write-SmokeJson -Path $codexState -Value @{ schema_version = 1; hook_executable = $standaloneHook }
        New-SmokeFile -Path $codexLockPath -Text ''
        Write-SmokeJson -Path $movedOwnership -Value $forcedOwnership
    }
    & $newForcedCase $postimage
    $result = Complete-DefenseClawForcedUninstall -Result ([pscustomobject]@{ ok = $true }) `
        -MovedStateRoot $moved -MovedInstallReceipt '' -Layout $forcedLayout
    Assert-Smoke (Test-SmokeSameBytes -Path $codexPolicy -Expected $adminCodex) 'the forced uninstall did not put the administrator''s Codex requirements.toml back'
    Assert-Smoke (-not [IO.File]::Exists($codexState) -and -not [IO.File]::Exists($codexLockPath)) 'the forced uninstall left DefenseClaw''s Codex state beside the restored policy'
    Assert-Smoke ($script:removedTrees -contains $moved -and $null -eq $result.PSObject.Properties['forced_state_root_kept']) 'the forced uninstall kept a StateRoot nothing needs'
    Assert-Smoke ([bool]$result.forced) 'the forced uninstall result is not marked forced'

    # The file changed after DefenseClaw wrote it: it stays as found, and so
    # does the moved StateRoot with the only copy of the original.
    $edited = [Text.Encoding]::UTF8.GetBytes("approval_policy = `"on-request`"`n[hooks]`nmanaged = true`n")
    & $newForcedCase $edited
    $result = Complete-DefenseClawForcedUninstall -Result ([pscustomobject]@{ ok = $true }) `
        -MovedStateRoot $moved -MovedInstallReceipt '' -Layout $forcedLayout
    Assert-Smoke (Test-SmokeSameBytes -Path $codexPolicy -Expected $edited) 'the forced uninstall changed a Codex policy edited after install'
    Assert-Smoke ([IO.File]::Exists($movedOwnership) -and $script:removedTrees.Count -eq 0) 'the forced uninstall deleted the only copy of the administrator''s Codex original'
    Assert-Smoke ([string]$result.forced_state_root_kept -like "$moved*codex-requirements-ownership.json*") "the kept StateRoot is not named: $($result.forced_state_root_kept)"

    # A Codex state for another hook: not this deployment's to restore.
    & $newForcedCase $postimage
    Write-SmokeJson -Path $codexState -Value @{ schema_version = 1; hook_executable = $scHook }
    $result = Complete-DefenseClawForcedUninstall -Result ([pscustomobject]@{ ok = $true }) `
        -MovedStateRoot $moved -MovedInstallReceipt '' -Layout $forcedLayout
    Assert-Smoke ((Test-SmokeSameBytes -Path $codexPolicy -Expected $postimage) -and [IO.File]::Exists($movedOwnership)) 'the forced uninstall restored a Codex policy another deployment owns'

    # No Codex record: the moved StateRoot goes as before.
    Reset-SmokeTree
    $script:removedTrees.Clear()
    New-SmokeFile -Path ([IO.Path]::Combine($moved, 'audit.db')) -Text 'x'
    $result = Complete-DefenseClawForcedUninstall -Result ([pscustomobject]@{ ok = $true }) `
        -MovedStateRoot $moved -MovedInstallReceipt '' -Layout $forcedLayout
    Assert-Smoke ($script:removedTrees -contains $moved -and -not [IO.Directory]::Exists($moved)) 'the forced uninstall kept a StateRoot without a Codex record'

    Microsoft.PowerShell.Utility\Write-Output 'PASS enterprise-nuclear-purge-smoke'
}
finally {
    foreach ($junction in @($script:junctions)) {
        try { [IO.Directory]::Delete($junction, $false) } catch { }
    }
    if ([IO.Directory]::Exists($script:tmp)) {
        Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue |
            Microsoft.PowerShell.Core\ForEach-Object { $_.Attributes = [IO.FileAttributes]::Normal }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
