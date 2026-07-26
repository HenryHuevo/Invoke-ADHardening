function Invoke-ADHAuditPhase {
    <#
    .SYNOPSIS
        Runs the read-only audit phase: dispatches each Test-* check,
        aggregates findings, and emits the report set.
    .PARAMETER Checks
        Array of hashtables with Id/Test/Fix keys (from the orchestrator's
        $checkRegistry).
    .PARAMETER OutputPath
        Directory to write reports into. Must already exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Checks,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($check in $Checks) {
        $cmd = Get-Command -Name $check.Test -ErrorAction SilentlyContinue
        if (-not $cmd) {
            Write-ADHLog -Level WARN -Message "$($check.Id) skipped: $($check.Test) not yet implemented" -Console
            continue
        }

        try {
            $finding = & $check.Test
            if ($finding) {
                $findings.Add($finding)
                # Persist every finding to findings.jsonl so Implement mode can
                # consume the full audit (not just crashes). The Write-ADHLog
                # call is read-only — it only appends to log/JSONL files.
                $level = switch ($finding.Status) {
                    'Pass'    { 'PASS' }
                    'Fail'    { 'FAIL' }
                    'Warning' { 'WARN' }
                    'Error'   { 'ERROR' }
                    default   { 'CHECK' }
                }
                Write-ADHLog -Level $level `
                    -Message "$($check.Id) $($finding.CheckName): $($finding.Status)" `
                    -Finding $finding -Console
            }
        } catch {
            $errFinding = New-ADHFinding `
                -CheckId $check.Id `
                -CheckName $check.Test `
                -Category 'Unknown' `
                -Severity 'Info' `
                -Status 'Error' `
                -Description "Check threw an unhandled exception: $($_.Exception.Message)" `
                -Evidence @{ Exception = $_.Exception.ToString() }
            $findings.Add($errFinding)
            Write-ADHLog -Level ERROR -Message "$($check.Id) crashed: $($_.Exception.Message)" -Finding $errFinding -Console
        }
    }

    $reportPaths = Export-ADHReport -Findings $findings -OutputPath $OutputPath

    # NB: wrap each Where-Object result in @() before .Count. A pipeline that
    # yields a single object returns a scalar whose .Count renders blank on
    # Windows PowerShell 5.1 (the lab DC), which is why single-count statuses
    # such as Pass / Error / NotApplicable came back empty in the first report.
    $bySeverity = $findings | Where-Object Status -eq 'Fail' | Group-Object Severity |
        Select-Object @{N='Severity';E={$_.Name}}, Count
    $pass  = @($findings | Where-Object Status -eq 'Pass').Count
    $fail  = @($findings | Where-Object Status -eq 'Fail').Count
    $warn  = @($findings | Where-Object Status -eq 'Warning').Count
    $err   = @($findings | Where-Object Status -eq 'Error').Count
    $na    = @($findings | Where-Object Status -eq 'NotApplicable').Count

    $crit  = @($bySeverity | Where-Object Severity -eq 'Critical').Count
    $high  = @($bySeverity | Where-Object Severity -eq 'High').Count
    $med   = @($bySeverity | Where-Object Severity -eq 'Medium').Count
    $low   = @($bySeverity | Where-Object Severity -eq 'Low').Count

    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ("Summary: {0} Critical, {1} High, {2} Medium, {3} Low (failing) | {4} Pass, {5} Warn, {6} Error, {7} N/A" -f `
        $crit,$high,$med,$low,$pass,$warn,$err,$na) -ForegroundColor White
    Write-Host "Reports written to: $OutputPath" -ForegroundColor White
    foreach ($p in $reportPaths.GetEnumerator()) {
        Write-Host ("  - {0,-6} {1}" -f $p.Key, $p.Value) -ForegroundColor Gray
    }
    Write-Host ''
    if ($fail -gt 0) {
        Write-Host 'To remediate: Invoke-ADHardening -Mode Implement' -ForegroundColor Yellow
    }
    Write-Host '================================================================' -ForegroundColor Cyan

    return $findings
}
