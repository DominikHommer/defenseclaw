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
# below one, and not in a folder above one (GAP-0011). The functions run from
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
    'Invoke-DefenseClawNuclearUninstall'
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
function Remove-DefenseClawManagedUserRuntimeLeftovers {
    return [pscustomobject]@{ removed = [string[]]@(); remaining = [string[]]@() }
}

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
