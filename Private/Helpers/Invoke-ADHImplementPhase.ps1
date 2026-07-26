function Invoke-ADHImplementPhase {
    <#
    .SYNOPSIS
        Implement (remediation) phase: consumes a saved audit, previews every
        applicable fix with -WhatIf, then prompts the operator to apply them
        (all at once, or one by one), re-runs each Test-* to verify, and emits
        an implementation report.
    .DESCRIPTION
        This phase deliberately does NOT re-discover findings. It loads a saved
        audit (findings.jsonl, falling back to report.json), filters to
        auto-fixable Fail/Warning findings that are still in scope, and then:

          1. Previews every applicable fix under -WhatIf (no state is changed).
          2. Asks the operator y/N whether to actually apply the changes.
          3. If yes, asks whether to apply them [A]ll at once (no further
             prompts) or [O]ne-by-one (per-finding [A]pply/[S]kip/skip
             [R]est/[Q]uit).

        Flag semantics:
          -Confirm:$false runs unattended (no prompts). In this mode -Force
                          decides apply vs. dry run: with -Force every fix is
                          applied; without it every fix runs under -WhatIf.
                          The interactive preview/confirm flow above is skipped.
          -Force          only meaningful with -Confirm:$false (see above). In
                          an interactive run the on-screen y/N + per-finding
                          prompts are the operator's acknowledgement, so -Force
                          is not required to apply.

        NOTE FOR MAINTAINERS: this helper is intentionally NOT part of the
        read-only audit path scanned by Tests/AuditPhase.ReadOnly.Tests.ps1.
        It is only reached in Implement mode and is expected to invoke the
        Set-* fixes. Do not add it to $auditFiles in that test.
    .PARAMETER Checks
        Array of hashtables with Id/Test/Fix keys (the filtered $checkRegistry
        from the orchestrator). -IncludeCheckIds / -ExcludeCheckIds filtering
        is already applied upstream and is honoured here as the in-scope set.
    .PARAMETER ReportPath
        Path to a Reports/<timestamp> directory containing the saved audit. If
        omitted, the most recent sibling run of -OutputPath is used.
    .PARAMETER OutputPath
        Directory to write the implementation report into. Must already exist.
    .PARAMETER Force
        Unattended (-Confirm:$false) runs only: actually apply fixes instead of
        previewing them under -WhatIf. Ignored by the interactive flow.
    .OUTPUTS
        The array of per-finding result objects (also written to
        implementation-summary.json and implementation-report.html).
    .EXAMPLE
        Invoke-ADHImplementPhase -Checks $reg -OutputPath $out
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][object[]]$Checks,
        [string]$ReportPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$Force,
        [int]$StaleAfterDays = 7
    )

    # ---- 1. Locate the audit input -----------------------------------------
    $sourceDir = $null
    if ($ReportPath) {
        if (-not (Test-Path $ReportPath)) {
            Write-ADHLog -Level ERROR -Message "Implement: ReportPath not found: $ReportPath" -Console
            return
        }
        $sourceDir = (Resolve-Path $ReportPath).Path
    } else {
        $reportsRoot = Split-Path -Parent $OutputPath
        $candidates = Get-ChildItem -Path $reportsRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne (Resolve-Path $OutputPath).Path } |
            Where-Object { (Test-Path (Join-Path $_.FullName 'findings.jsonl') -PathType Leaf) -or
                           (Test-Path (Join-Path $_.FullName 'report.json') -PathType Leaf) } |
            Sort-Object Name -Descending
        if (-not $candidates) {
            Write-ADHLog -Level ERROR -Message "Implement: no prior audit found under $reportsRoot. Run an audit first, or pass -ReportPath." -Console
            return
        }
        $sourceDir = $candidates[0].FullName
    }

    $jsonl = Join-Path $sourceDir 'findings.jsonl'
    $json  = Join-Path $sourceDir 'report.json'

    $allFindings = @()
    if (Test-Path $jsonl -PathType Leaf) {
        $allFindings = @(Get-Content -Path $jsonl |
            Where-Object { $_.Trim() } |
            ForEach-Object { $_ | ConvertFrom-Json })
    }
    if (-not $allFindings -and (Test-Path $json -PathType Leaf)) {
        $allFindings = @((Get-Content -Path $json -Raw) | ConvertFrom-Json)
    }
    if (-not $allFindings) {
        Write-ADHLog -Level ERROR -Message "Implement: no findings could be loaded from $sourceDir" -Console
        return
    }

    Write-ADHLog -Level INFO -Message "Implement: loaded $($allFindings.Count) finding(s) from $sourceDir" -Console

    # ---- 1a. Stale-audit warning -------------------------------------------
    $dirName = Split-Path $sourceDir -Leaf
    [DateTime]$auditDate = [DateTime]::MinValue
    if ([DateTime]::TryParseExact($dirName, 'yyyy-MM-dd_HHmmss',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None, [ref]$auditDate)) {
        $ageDays = ((Get-Date) - $auditDate).TotalDays
        if ($ageDays -gt $StaleAfterDays) {
            Write-ADHLog -Level WARN -Message ("Implement: audit is {0:N1} days old (> {1}). AD state may have drifted." -f $ageDays, $StaleAfterDays) -Console
            if ($ConfirmPreference -ne 'None') {
                $ans = Read-Host "Continue remediating from this stale audit? [y/N]"
                if ($ans -notmatch '^(y|yes)$') {
                    Write-ADHLog -Level INFO -Message 'Implement: aborted (stale audit declined)' -Console
                    return
                }
            }
        }
    }

    # ---- 2. Filter to actionable findings ----------------------------------
    $inScope = @($Checks | ForEach-Object { $_.Id })
    $applicable = @($allFindings | Where-Object {
        $_.Status -in @('Fail','Warning') -and
        $_.AutoFixAvailable -eq $true -and
        $_.FixFunction -and
        $_.CheckId -in $inScope
    })

    if (-not $applicable) {
        Write-ADHLog -Level INFO -Message 'Implement: no applicable findings to remediate.' -Console
        return
    }

    $noPrompt = ($ConfirmPreference -eq 'None')

    # ---- helpers -----------------------------------------------------------
    $newResult = {
        param($finding)
        [PSCustomObject]@{
            CheckId      = $finding.CheckId
            CheckName    = $finding.CheckName
            Severity     = $finding.Severity
            FixFunction  = $finding.FixFunction
            Action       = 'Skipped'
            BeforeStatus = $finding.Status
            AfterStatus  = $null
            Verified     = $false
            ChangeRecord = $null
            Notes        = ''
        }
    }

    # Apply (or, with -WhatIf, preview) one fix and record the outcome on
    # $result, which is mutated in place. $dryRun => invoke under -WhatIf and
    # never mutate AD/GPO state.
    $applyOneFix = {
        param($finding, $check, $result, [bool]$dryRun)

        $fixCmd = Get-Command -Name $check.Fix -ErrorAction SilentlyContinue
        if (-not $fixCmd) {
            Write-ADHLog -Level WARN -Message "Implement: fix function '$($check.Fix)' not found for $($finding.CheckId); skipping." -Console
            $result.Action = 'Failed'
            $result.Notes  = "Fix function '$($check.Fix)' not found"
            return
        }

        # A real apply is the operator's acknowledgement: forward whichever
        # opt-in switches the fix declares so it actually takes effect.
        # -LinkAtDomainRoot links the hardening GPO at the domain root (an
        # unlinked GPO is not a remediation); the -IAcknowledge* switches
        # satisfy the fix's typed-confirmation gate. Not forwarded in a dry run.
        $fixArgs = @{}
        foreach ($p in @('LinkAtDomainRoot',
                         'IAcknowledgeThisCanBreakLegacyApps',
                         'IAcknowledgeThisAffectsAllUsers')) {
            if ($fixCmd.Parameters.ContainsKey($p)) { $fixArgs[$p] = $true }
        }

        try {
            Write-ADHLog -Level FIX -Message ("Implement: {0} {1} {2}" -f `
                $(if ($dryRun) { 'previewing' } else { 'applying' }), $finding.CheckId, $check.Fix) -Console

            if ($dryRun) {
                $rec = & $check.Fix -WhatIf
            } else {
                $rec = & $check.Fix @fixArgs
            }
            $result.ChangeRecord = $rec

            # Verify by re-running the check.
            $after = & $check.Test
            if ($after) { $result.AfterStatus = $after.Status }

            if ($dryRun) {
                $result.Action = 'WhatIf'
                $result.Notes  = 'Previewed only (no changes applied)'
            } elseif ($rec -and $rec.Success -and $result.AfterStatus -eq 'Pass') {
                $result.Action   = 'Applied'
                $result.Verified = $true
            } elseif ($rec -and $rec.Success) {
                $result.Action = 'Applied'
                $result.Notes  = "Fix applied but the verification re-check still returns '$($result.AfterStatus)'. This can be policy-propagation delay (gpupdate /force, AD replication), but can also mean the fix did not take effect (e.g. a higher-precedence GPO overrides the setting, or the GPO is not linked). Investigate before treating this as remediated."
            } else {
                $result.Action = 'Failed'
                if ($rec -and $rec.ErrorMessage) { $result.Notes = $rec.ErrorMessage }
            }
        } catch {
            Write-ADHLog -Level ERROR -Message "Implement: fix $($check.Fix) threw: $($_.Exception.Message)" -Console
            $result.Action = 'Failed'
            $result.Notes  = $_.Exception.Message
        }
    }

    # Mark a result as operator-skipped, clearing any preview data.
    $markSkipped = {
        param($result, $note)
        $result.Action       = 'Skipped'
        $result.ChangeRecord = $null
        $result.AfterStatus  = $null
        $result.Verified     = $false
        $result.Notes        = $note
    }

    $printFinding = {
        param($finding)
        Write-Host ''
        Write-Host ("[{0}] {1}  ({2})" -f $finding.CheckId, $finding.CheckName, $finding.Severity) -ForegroundColor White
        Write-Host ("    Status: {0}    Fix: {1}" -f $finding.Status, $finding.FixFunction) -ForegroundColor Gray
        if ($finding.Description) {
            Write-Host ("    {0}" -f $finding.Description) -ForegroundColor Gray
        }
    }

    # Writes the summary JSON + HTML report and prints the summary banner.
    $completeRun = {
        param($results, [bool]$dryRun)

        $applied = @($results | Where-Object Action -eq 'Applied').Count
        $whatif  = @($results | Where-Object Action -eq 'WhatIf').Count
        $skipped = @($results | Where-Object Action -eq 'Skipped').Count
        $failed  = @($results | Where-Object Action -eq 'Failed').Count

        $summary = [PSCustomObject]@{
            Timestamp  = [DateTime]::UtcNow.ToString('o')
            SourcePath = $sourceDir
            OutputPath = $OutputPath
            DryRun     = [bool]$dryRun
            Total      = $results.Count
            Applied    = $applied
            WhatIf     = $whatif
            Skipped    = $skipped
            Failed     = $failed
            Results    = $results
        }
        $summary | ConvertTo-Json -Depth 10 |
            Out-File -FilePath (Join-Path $OutputPath 'implementation-summary.json') -Encoding UTF8

        $htmlPath = New-ADHImplementationReport -Results $results -SourcePath $sourceDir -OutputPath $OutputPath -DryRun:$dryRun

        Write-Host ''
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host ("Implement summary: {0} Applied, {1} WhatIf, {2} Skipped, {3} Failed" -f `
            $applied, $whatif, $skipped, $failed) -ForegroundColor White
        Write-Host ("Report: {0}" -f $htmlPath) -ForegroundColor Gray
        Write-Host '================================================================' -ForegroundColor Cyan
    }

    $results = New-Object System.Collections.Generic.List[object]

    # ===== Unattended path (-Confirm:$false) ================================
    # No prompts: -Force applies, otherwise everything runs as a -WhatIf dry run.
    if ($noPrompt) {
        $dryRun = (-not $Force) -or $WhatIfPreference

        Write-Host ''
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host ("Implement mode: {0} applicable finding(s){1}" -f $applicable.Count,
            $(if ($dryRun) { ' (DRY RUN - WhatIf, no changes will be made)' } else { '' })) -ForegroundColor White
        Write-Host '================================================================' -ForegroundColor Cyan

        foreach ($finding in $applicable) {
            $check  = $Checks | Where-Object { $_.Id -eq $finding.CheckId } | Select-Object -First 1
            $result = & $newResult $finding
            & $applyOneFix $finding $check $result $dryRun
            $results.Add($result)
        }

        & $completeRun $results $dryRun
        return $results
    }

    # ===== Interactive path =================================================
    # Pair each finding with its check + result object up front.
    $items = foreach ($finding in $applicable) {
        [PSCustomObject]@{
            Finding = $finding
            Check   = ($Checks | Where-Object { $_.Id -eq $finding.CheckId } | Select-Object -First 1)
            Result  = (& $newResult $finding)
        }
    }
    foreach ($i in $items) { $results.Add($i.Result) }

    # ---- 3. Preview pass (always -WhatIf, no changes made) ------------------
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ("Implement preview: {0} applicable finding(s) (DRY RUN - WhatIf, no changes will be made)" -f $applicable.Count) -ForegroundColor White
    Write-Host '================================================================' -ForegroundColor Cyan

    foreach ($i in $items) {
        & $printFinding $i.Finding
        & $applyOneFix $i.Finding $i.Check $i.Result $true
    }

    # ---- 4. Confirm whether to actually apply ------------------------------
    Write-Host ''
    $apply = $null
    while ($null -eq $apply) {
        $raw = Read-Host ("Apply the {0} change(s) previewed above? [y/N]" -f $applicable.Count)
        switch -Regex ($raw) {
            '^(y|yes)$'    { $apply = $true }
            '^(n|no|)$'    { $apply = $false }
            default        { Write-Host '    Please answer y or N.' -ForegroundColor Yellow }
        }
    }

    if (-not $apply) {
        Write-ADHLog -Level INFO -Message 'Implement: operator declined to apply; preview only.' -Console
        & $completeRun $results $true   # results hold the WhatIf preview
        return $results
    }

    # ---- 5. All at once, or one by one? ------------------------------------
    $batch = $null
    while ($null -eq $batch) {
        $raw = Read-Host '    Apply [A]ll at once, or review [O]ne-by-one?'
        switch -Regex ($raw) {
            '^(a|all)$'     { $batch = $true }
            '^(o|one|1)$'   { $batch = $false }
            default         { Write-Host '    Please answer A or O.' -ForegroundColor Yellow }
        }
    }

    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ("Applying {0} change(s)..." -f $applicable.Count) -ForegroundColor White
    Write-Host '================================================================' -ForegroundColor Cyan

    # ---- 6. Apply ----------------------------------------------------------
    if ($batch) {
        # All at once (confirm-all): apply every finding, no further prompts.
        foreach ($i in $items) {
            & $printFinding $i.Finding
            & $applyOneFix $i.Finding $i.Check $i.Result $false
        }
    } else {
        # One by one: per-finding [A]pply / [S]kip / skip [R]est / [Q]uit.
        $skipRest = $false
        $quit     = $false

        foreach ($i in $items) {
            if ($skipRest) {
                & $markSkipped $i.Result 'Skipped (operator chose Skip Rest)'
                continue
            }

            & $printFinding $i.Finding

            $choice = $null
            while (-not $choice) {
                $raw = Read-Host '    [A]pply / [S]kip / Skip [R]est / [Q]uit'
                switch -Regex ($raw) {
                    '^(a|apply)$' { $choice = 'A' }
                    '^(s|skip)$'  { $choice = 'S' }
                    '^(r|rest)$'  { $choice = 'R' }
                    '^(q|quit)$'  { $choice = 'Q' }
                    default       { Write-Host '    Please answer A, S, R, or Q.' -ForegroundColor Yellow }
                }
            }

            switch ($choice) {
                'Q' {
                    Write-ADHLog -Level INFO -Message "Implement: operator quit at $($i.Finding.CheckId)" -Console
                    & $markSkipped $i.Result 'Skipped (operator quit)'
                    $quit = $true
                }
                'R' {
                    & $markSkipped $i.Result 'Skipped (operator chose Skip Rest)'
                    $skipRest = $true
                }
                'S' {
                    Write-ADHLog -Level INFO -Message "Implement: skipped $($i.Finding.CheckId)" -Console
                    & $markSkipped $i.Result 'Skipped by operator'
                }
                'A' {
                    & $applyOneFix $i.Finding $i.Check $i.Result $false
                }
            }

            if ($quit) { break }
        }

        if ($quit) {
            Write-ADHLog -Level INFO -Message 'Implement: quit before completion - no implementation report written.' -Console
            return $results
        }
    }

    # ---- 7. Reports --------------------------------------------------------
    & $completeRun $results $false
    return $results
}
