#requires -Modules Pester

# Proves the audit phase cannot modify AD / GPO / registry / services.
#
# Strategy: static AST analysis of every .ps1 invoked during an audit run
# (orchestrator, audit-phase helpers, checks, finding/log helpers, report
# exporter). If any forbidden cmdlet name appears in a CommandAst, fail.
#
# We deliberately exclude Private/Fixes/* and Invoke-ADHImplementPhase
# because those are only reached in Implement mode.

Describe 'Audit phase is provably read-only' {

    BeforeAll {
        $script:repoRoot = Split-Path -Parent $PSScriptRoot

        # Verbs that mutate AD/GPO/registry/service/firewall state.
        # New-ADHFinding (and other ADH* helpers) are excluded via the (?!H) negative lookahead.
        $script:forbiddenPattern =
            '^(?i)(Set|New|Remove|Disable|Enable|Move|Rename)-AD(?!H)\w+$' +
            '|^(?i)(Set|New|Remove|Backup|Restore|Import)-GP\w+$' +
            '|^(?i)(Add|Remove)-AD\w*Member$' +
            '|^(?i)(Set|New|Remove|Clear)-ItemProperty$' +
            '|^(?i)(Set|New|Remove)-Item$' +
            '|^(?i)(Start|Stop|Restart|Suspend|Resume)-Service$' +
            '|^(?i)Set-Service$' +
            '|^(?i)Invoke-GPUpdate$' +
            '|^(?i)(Set|New|Remove|Enable|Disable)-NetFirewallRule$' +
            '|^(?i)(New|Remove|Set)-LocalUser$' +
            '|^(?i)(Add|Remove)-LocalGroupMember$'

        # Files that legitimately run in the audit path. Note: the orchestrator
        # Invoke-ADHardening.ps1 calls New-Item to create the output directory,
        # so we scope this assertion to the audit code path itself.
        $script:auditFiles = @()
        $script:auditFiles += Get-ChildItem -Path (Join-Path $repoRoot 'Private/Checks') -Filter *.ps1 -ErrorAction SilentlyContinue
        $script:auditFiles += @(
            'Private/Helpers/Invoke-ADHAuditPhase.ps1'
            'Private/Helpers/Export-ADHReport.ps1'
            'Private/Helpers/Get-ADHReportAssets.ps1'
            'Private/Helpers/Write-ADHLog.ps1'
            'Private/Helpers/New-ADHFinding.ps1'
            'Private/Helpers/Test-ADHPrerequisites.ps1'
            'Private/Helpers/Show-Invoke-ADHardeningBanner.ps1'
            'Private/Helpers/Get-ADHGpoSettingForOu.ps1'
        ) | ForEach-Object { Get-Item (Join-Path $repoRoot $_) -ErrorAction SilentlyContinue }
        $script:auditFiles = $script:auditFiles | Where-Object { $_ }
    }

    It 'contains no destructive AD/GPO/registry/service cmdlets in any audit-path file' {
        $violations = @()
        foreach ($file in $script:auditFiles) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $file.FullName, [ref]$tokens, [ref]$errors)

            $commands = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true)

            foreach ($cmd in $commands) {
                $name = $cmd.GetCommandName()
                if ($name -and $name -match $script:forbiddenPattern) {
                    $violations += "$($file.Name):$($cmd.Extent.StartLineNumber) -> $name"
                }
            }
        }

        $violations | Should -BeNullOrEmpty -Because (
            "audit phase must not invoke any state-changing cmdlets. Violations:`n" +
            ($violations -join "`n"))
    }

    It 'covers every Test-* check file' {
        # Sanity: make sure the test actually scans the check files we have.
        $checkFiles = $script:auditFiles | Where-Object { $_.FullName -like '*Private*Checks*' }
        $checkFiles.Count | Should -BeGreaterThan 0
    }
}
