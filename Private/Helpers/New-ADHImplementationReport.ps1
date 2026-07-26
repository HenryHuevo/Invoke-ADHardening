function New-ADHImplementationReport {
    <#
    .SYNOPSIS
        Renders the Implement-phase results as a self-contained HTML report.
    .DESCRIPTION
        Shares the audit report's design system (Get-ADHReportStyle /
        Get-ADHReportScript), so the two pages read as one tool: inline CSS/JS
        with no external requests, a dark/light toggle defaulting to dark, no
        chart, no severity rating, and one collapsed row per item that opens
        onto its detail.

        A row here is one fix attempt, in the order it was made. Collapsed it
        shows the check id, the action taken, the check name, and the step
        number; opened it shows the before -> after re-check transition and
        whether it was verified, which fix function ran, the note the phase
        recorded, and the raw change record.
    .PARAMETER Results
        Array of per-finding result objects from Invoke-ADHImplementPhase, in
        the order they were processed. Each has CheckId, CheckName, Severity,
        FixFunction, Action, BeforeStatus, AfterStatus, Verified, ChangeRecord,
        and Notes. Severity is accepted but not rendered.
    .PARAMETER SourcePath
        The Reports/<timestamp> directory the audit was loaded from.
    .PARAMETER OutputPath
        Directory to write implementation-report.html into.
    .PARAMETER DryRun
        Whether the run was a -WhatIf preview (changes the header banner).
    .OUTPUTS
        System.String. The path to the written implementation-report.html.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$DryRun
    )

    $generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    $domain = try { (Get-ADDomain -ErrorAction Stop).DNSRoot } catch { 'unknown domain' }
    $sourceReport = Join-Path $SourcePath 'report.html'

    # Hue token per action (see Get-ADHReportStyle).
    $actionSig  = @{ Applied = 'jade'; WhatIf = 'violet'; Skipped = 'quiet'; Failed = 'rose' }
    $actionKey  = @{ Applied = 'applied'; WhatIf = 'whatif'; Skipped = 'skipped'; Failed = 'failed' }
    $actionPrio = @{ Failed = 0; Applied = 1; WhatIf = 2; Skipped = 3 }

    # NB: wrap in @() before .Count - a single-element pipeline result is a
    # scalar whose .Count renders blank on Windows PowerShell 5.1.
    $totals = @{
        applied = @($Results | Where-Object { $_.Action -eq 'Applied' }).Count
        whatif  = @($Results | Where-Object { $_.Action -eq 'WhatIf'  }).Count
        skipped = @($Results | Where-Object { $_.Action -eq 'Skipped' }).Count
        failed  = @($Results | Where-Object { $_.Action -eq 'Failed'  }).Count
    }
    $total    = @($Results).Count
    $verified = @($Results | Where-Object { $_.Verified }).Count
    $noun     = if ($total -eq 1) { 'fix' } else { 'fixes' }

    if ($DryRun) {
        $headline = "$($totals.whatif) of $total $noun previewed"
        $subline  = 'Nothing was changed.'
    }
    elseif ($totals.failed -gt 0) {
        $headline = "$($totals.failed) of $total $noun failed"
        $subline  = "$($totals.applied) applied, $($totals.skipped) skipped."
    }
    elseif ($totals.applied -eq 0) {
        $headline = "No $noun applied"
        $subline  = "$($totals.skipped) skipped, $($totals.whatif) previewed."
    }
    else {
        $headline = "$($totals.applied) of $total $noun applied"
        $subline  = "$verified verified by re-check."
    }

    $order = 0
    $records = foreach ($r in $Results) {
        $act  = [string]$r.Action
        $sig  = $actionSig[$act];  if (-not $sig) { $sig = 'quiet' }
        $key  = $actionKey[$act];  if (-not $key) { $key = 'skipped' }
        $prio = $actionPrio[$act]; if ($null -eq $prio) { $prio = 4 }

        # The before -> after transition is the whole point of this page, so it
        # leads the body rather than hiding in a table cell.
        $after = if ($r.AfterStatus) { Format-ADHHtmlText $r.AfterStatus '' } else { 'not re-checked' }
        $verdict = if ($r.Verified) { '<span class="flow-ok">verified</span>' }
                   elseif ($act -eq 'Applied') { '<span class="flow-no">not confirmed</span>' }
                   else { '' }
        $flowHtml = @"
<div class="flow">
  <span class="flow-k">Re-check</span>
  <span class="flow-a">$(Format-ADHHtmlText $r.BeforeStatus '')</span>
  <span class="flow-arrow">&#8594;</span>
  <span class="flow-b">$after</span>
  $verdict
</div>
"@

        $rail = @()
        if ($r.FixFunction) {
            $rail += "<div class=""rail-row""><span class=""rail-k"">fix function</span><span class=""rail-v""><code>$(Format-ADHHtmlText $r.FixFunction '')</code></span></div>"
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$r.Notes)) {
            $rail += "<div class=""rail-row""><span class=""rail-k"">what happened</span><span class=""rail-v"">$(Format-ADHHtmlText $r.Notes '')</span></div>"
        }
        $railHtml = if ($rail) { "<div class=""rail"">$($rail -join '')</div>" } else { '' }

        $changeHtml = ''
        if ($r.ChangeRecord) {
            $json = ($r.ChangeRecord | ConvertTo-Json -Depth 10)
            $changeHtml = @"
<div class="drops">
  <details class="drop">
    <summary><span class="drop-t">Change record</span><span class="drop-n">before / after</span></summary>
    <pre class="code">$(Format-ADHHtmlText $json '')</pre>
  </details>
</div>
"@
        }

        $out = @"
<details class="rec" id="$($r.CheckId)" data-sig="$sig" data-filter="$key" data-order="$order" data-prio="$prio" data-id="$($r.CheckId)" data-cat="$(Format-ADHHtmlText $act '')">
  <summary class="rec-sum">
    <span class="rec-id">$(Format-ADHHtmlText $r.CheckId '')</span>
    <span class="rec-state"><span class="dot"></span>$(Format-ADHHtmlText $act '')</span>
    <span class="rec-name">$(Format-ADHHtmlText $r.CheckName '')</span>
    <span class="rec-cat">step $($order + 1) of $total</span>
  </summary>
  <div class="rec-body">
    $flowHtml
    $railHtml
    $changeHtml
  </div>
</details>
"@
        $order++
        $out
    }

    $chipDefs = @(
        @{ k = 'failed';  sig = 'rose';   label = 'Failed';  n = $totals.failed  }
        @{ k = 'applied'; sig = 'jade';   label = 'Applied'; n = $totals.applied }
        @{ k = 'whatif';  sig = 'violet'; label = 'WhatIf';  n = $totals.whatif  }
        @{ k = 'skipped'; sig = 'quiet';  label = 'Skipped'; n = $totals.skipped }
    )
    $chipHtml = -join ($chipDefs | ForEach-Object {
        $dis = if ($_.n -eq 0) { ' disabled' } else { '' }
        "<button type=""button"" class=""chip"" data-filter=""$($_.k)"" data-sig=""$($_.sig)""$dis><span class=""dot""></span>$($_.label)<span class=""chip-n"">$($_.n)</span></button>"
    })

    $notice = ''
    if ($DryRun) {
        $notice = @"
<div class="notice" data-sig="violet">
  <span class="notice-k">Dry run</span>
  <span>Every fix ran under -WhatIf. Nothing was changed. Re-run with -Force to apply.</span>
</div>
"@
    }
    elseif ($totals.failed -gt 0) {
        $failNoun = if ($totals.failed -eq 1) { 'fix' } else { 'fixes' }
        $notice = @"
<div class="notice" data-sig="rose">
  <span class="notice-k">Action needed</span>
  <span>$($totals.failed) $failNoun did not complete. Read the note on each before re-running.</span>
</div>
"@
    }

    $srcEnc    = [System.Net.WebUtility]::HtmlEncode([string]$sourceReport)
    $css       = Get-ADHReportStyle
    $js        = Get-ADHReportScript
    $bootTheme = Get-ADHReportBootScript

    @"
<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>Invoke-ADHardening implement - $(Format-ADHHtmlText $domain '')</title>
<script>$bootTheme</script>
<style>
$css
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <span class="brand">Invoke-ADHardening &#183; implement</span>
    <button type="button" class="theme" id="theme" aria-label="Switch to light theme">
      <span class="glyph" aria-hidden="true">&#9728;</span><span class="label">Light</span>
    </button>
  </header>

  <h1 class="domain">$(Format-ADHHtmlText $domain '')</h1>
  <p class="headline">$(Format-ADHHtmlText $headline '') <span class="quiet">$(Format-ADHHtmlText $subline '')</span></p>
  <p class="stamp">$(Format-ADHHtmlText $generated '') &#183; from audit <a href="$srcEnc">$(Format-ADHHtmlText $SourcePath '')</a></p>

  $notice

  <div class="controls">
    <button type="button" class="chip chip-all" data-filter="all" aria-pressed="true"><span class="dot"></span>All</button>
$chipHtml
    <span class="spacer"></span>
    <span class="readout" id="readout" data-noun="$noun">$total $noun</span>
    <button type="button" class="ghost-btn" id="expand" data-mode="expand">Expand all</button>
    <label class="sortwrap" for="sortby">Sort
      <select id="sortby">
        <option value="order">Run order</option>
        <option value="priority">Outcome</option>
        <option value="id">Check ID</option>
      </select>
    </label>
  </div>

  <main class="records" id="records">
$($records -join "`n")
  </main>
  <p class="empty" id="empty" hidden>No fixes match this filter.</p>

  <footer class="foot">
    <span>Reports stay local. No telemetry, no upload.</span>
    <span>Alongside: implementation-summary.json &#183; changes.jsonl &#183; audit.log</span>
  </footer>
</div>

<script>
$js
</script>
</body>
</html>
"@ | Out-File -FilePath (Join-Path $OutputPath 'implementation-report.html') -Encoding UTF8

    return (Join-Path $OutputPath 'implementation-report.html')
}
