function Invoke-ADHardening {
    <#
    .SYNOPSIS
        Audits an AD environment against the 10 Invoke-ADHardening checks,
        and optionally remediates findings.
    .DESCRIPTION
        Default mode is 'Audit', which is read-only. 'Implement' mode
        consumes a saved audit report, previews each fix with -WhatIf, then
        prompts y/N to apply them - either all at once or one-by-one.
    .PARAMETER Mode
        'Audit' (default) or 'Implement'.
    .PARAMETER ReportPath
        For Implement mode: path to a Reports/<timestamp> directory
        containing findings.jsonl. If omitted, the most recent run is used.
    .PARAMETER IncludeCheckIds
        Run only these check IDs (e.g. 'ADH-001','ADH-003').
    .PARAMETER ExcludeCheckIds
        Skip these check IDs.
    .PARAMETER OutputPath
        Override the output directory. Defaults to Reports/<timestamp>.
    .PARAMETER NoBanner
        Skip the banner / continue prompt.
    .PARAMETER Force
        Unattended (-Confirm:$false) Implement runs only: actually apply fixes
        instead of previewing them under -WhatIf. The interactive flow ignores
        -Force - the on-screen y/N + per-finding prompts are the acknowledgement.
    .EXAMPLE
        Invoke-ADHardening
    .EXAMPLE
        Invoke-ADHardening -IncludeCheckIds ADH-001
    .EXAMPLE
        Invoke-ADHardening -Mode Implement -ReportPath .\Reports\2026-05-13_142201
    .EXAMPLE
        Invoke-ADHardening -Mode Implement                  # preview, then prompt to apply
    .EXAMPLE
        Invoke-ADHardening -Mode Implement -Force -Confirm:$false   # unattended apply
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('Audit','Implement')]
        [string]$Mode = 'Audit',
        [string]$ReportPath,
        [string[]]$IncludeCheckIds,
        [string[]]$ExcludeCheckIds,
        [string]$OutputPath,
        [switch]$NoBanner,
        [switch]$Force
    )

    $runTimestamp = (Get-Date).ToString('yyyy-MM-dd_HHmmss')
    if (-not $OutputPath) {
        $OutputPath = Join-Path $PSScriptRoot "..\Reports\$runTimestamp"
    }
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $script:ADHLogPath = (Resolve-Path $OutputPath).Path

    if (-not $NoBanner) {
        Show-Invoke-ADHardeningBanner
    }

    if (-not (Test-ADHPrerequisites)) {
        Write-Host "Prerequisites not met. See log for details." -ForegroundColor Red
        return
    }

    $checkRegistry = @(
        @{ Id = 'ADH-001'; Test = 'Test-LLMNR';                    Fix = 'Set-LLMNRDisabled' }
        @{ Id = 'ADH-002'; Test = 'Test-MachineAccountQuota';      Fix = 'Set-MachineAccountQuota' }
        @{ Id = 'ADH-003'; Test = 'Test-SMBSigning';               Fix = 'Set-SMBSigningRequired' }
        @{ Id = 'ADH-004'; Test = 'Test-LDAPSigning';              Fix = 'Set-LDAPSigningEnforced' }
        @{ Id = 'ADH-005'; Test = 'Test-IPv6Mitm6';                Fix = 'Set-IPv6Mitm6Mitigated' }
        @{ Id = 'ADH-006'; Test = 'Test-PreWin2000Group';          Fix = 'Set-PreWin2000GroupCleaned' }
        @{ Id = 'ADH-007'; Test = 'Test-Kerberoasting';            Fix = $null }
        @{ Id = 'ADH-008'; Test = 'Test-UnconstrainedDelegation';  Fix = $null }
        @{ Id = 'ADH-009'; Test = 'Test-PasswordPolicy';           Fix = 'Set-PasswordPolicyBaseline' }
        @{ Id = 'ADH-010'; Test = 'Test-ADCSMisconfig';            Fix = $null }
    )

    $checksToRun = $checkRegistry | Where-Object {
        $include = -not $IncludeCheckIds -or $_.Id -in $IncludeCheckIds
        $exclude = -not $ExcludeCheckIds -or $_.Id -notin $ExcludeCheckIds
        $include -and $exclude
    }

    switch ($Mode) {
        'Audit'     { $null = Invoke-ADHAuditPhase -Checks $checksToRun -OutputPath $script:ADHLogPath }
        'Implement' { Invoke-ADHImplementPhase -Checks $checksToRun -ReportPath $ReportPath -OutputPath $script:ADHLogPath -Force:$Force }
    }
}
