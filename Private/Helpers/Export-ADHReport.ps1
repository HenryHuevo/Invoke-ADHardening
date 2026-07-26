function Export-ADHReport {
    <#
    .SYNOPSIS
        Writes findings out as HTML, CSV, and JSON.
    .DESCRIPTION
        - report.json: full structured findings, depth 10.
        - report.csv:  one row per finding, Evidence/AffectedObjects/References flattened to JSON strings.
        - report.html: self-contained, styled, filterable/sortable.
        Returns a hashtable of format -> path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $jsonPath = Join-Path $OutputPath 'report.json'
    $csvPath  = Join-Path $OutputPath 'report.csv'
    $htmlPath = Join-Path $OutputPath 'report.html'

    $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8

    $flat = foreach ($f in $Findings) {
        [PSCustomObject]@{
            CheckId          = $f.CheckId
            CheckName        = $f.CheckName
            Category         = $f.Category
            Severity         = $f.Severity
            Status           = $f.Status
            Description      = $f.Description
            AffectedObjects  = ($f.AffectedObjects -join '; ')
            RemediationSteps = $f.RemediationSteps
            AutoFixAvailable = $f.AutoFixAvailable
            FixFunction      = $f.FixFunction
            References       = ($f.References -join '; ')
            Evidence         = ($f.Evidence | ConvertTo-Json -Compress -Depth 10)
            Timestamp        = $f.Timestamp.ToString('o')
        }
    }
    $flat | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    # Pass the run directory so the report's implement commands pin -ReportPath
    # to the audit being read, rather than whatever audit happens to be newest.
    $html = New-ADHHtmlReport -Findings $Findings -RunPath $OutputPath
    $html | Out-File -FilePath $htmlPath -Encoding UTF8

    return @{
        json = $jsonPath
        csv  = $csvPath
        html = $htmlPath
    }
}

function ConvertTo-ADHEvidenceMap {
    <#
    .SYNOPSIS
        Normalises a finding's Evidence to a plain hashtable.
    .DESCRIPTION
        Live checks hand back a hashtable; findings round-tripped through JSON
        come back as PSCustomObject. Both shapes read the same after this.
    .PARAMETER Evidence
        The Evidence value off a finding object.
    .OUTPUTS
        System.Collections.Hashtable
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Evidence)

    $map = @{}
    if ($null -eq $Evidence) { return $map }
    if ($Evidence -is [System.Collections.IDictionary]) {
        foreach ($k in $Evidence.Keys) { $map[[string]$k] = $Evidence[$k] }
    }
    else {
        foreach ($p in $Evidence.PSObject.Properties) { $map[[string]$p.Name] = $p.Value }
    }
    return $map
}

function New-ADHHtmlReport {
    <#
    .SYNOPSIS
        Renders the audit findings as a self-contained HTML report.
    .DESCRIPTION
        One page, zero external requests - CSS and JS are inline, from
        Get-ADHReportStyle / Get-ADHReportScript (shared with the implement
        report) - so it opens from a file:// path on an air-gapped jump box.

        There is no chart and no severity rating: status is the only signal the
        page carries, so the list of checks IS the overview. Each check renders
        as a collapsed row - id, status, name, category - that opens onto its
        description, how the check looked, what the result does not prove,
        affected objects, remediation, the fix command, evidence, and
        references.

        Colour encodes status only, and never alone - every status is spelled
        out beside its colour. Both the dark and light ramps were validated for
        colour-vision separation and contrast against their own surfaces.

        Ships dark (default) and light themes via a data-theme attribute on
        <html>. The choice persists to localStorage where the browser allows it
        on file:// URLs, and falls back to dark where it does not.

        NB: Severity is still carried on the finding object and still written to
        report.json / report.csv - it is only absent from this page.
    .PARAMETER Findings
        The finding objects produced by New-ADHFinding.
    .PARAMETER RunPath
        The Reports/<timestamp> directory this run is writing to. When supplied,
        the implement commands on the page pin -ReportPath to it, so an operator
        reading an older report remediates from that audit rather than from
        whichever audit happens to be newest. Omit it and the commands fall back
        to the phase's own newest-audit discovery.
    .OUTPUTS
        System.String. The complete HTML document.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [string]$RunPath
    )

    $generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    $domain = try { (Get-ADDomain -ErrorAction Stop).DNSRoot } catch { 'unknown domain' }

    $statusKey  = @{ Pass = 'pass'; Fail = 'fail'; Warning = 'warn'; Error = 'error'; NotApplicable = 'na' }
    $statusWord = @{ Pass = 'Pass'; Fail = 'Fail'; Warning = 'Warning'; Error = 'Error'; NotApplicable = 'N/A' }
    $statusPrio = @{ Fail = 0; Warning = 1; Error = 2; Pass = 3; NotApplicable = 4 }
    # Hue token per status (see Get-ADHReportStyle). Colour is keyed off data-sig
    # so both reports can share one stylesheet with different vocabularies.
    $statusSig  = @{ Pass = 'jade'; Fail = 'rose'; Warning = 'brass'; Error = 'violet'; NotApplicable = 'quiet' }

    # NB: wrap in @() before .Count. A single-element pipeline result is a
    # scalar whose .Count renders blank on Windows PowerShell 5.1, which left
    # the Pass / Error / N/A counts empty in the first lab report.
    $totals = @{
        pass  = @($Findings | Where-Object { $_.Status -eq 'Pass' }).Count
        fail  = @($Findings | Where-Object { $_.Status -eq 'Fail' }).Count
        warn  = @($Findings | Where-Object { $_.Status -eq 'Warning' }).Count
        error = @($Findings | Where-Object { $_.Status -eq 'Error' }).Count
        na    = @($Findings | Where-Object { $_.Status -eq 'NotApplicable' }).Count
    }
    $total     = @($Findings).Count
    $attention = $totals.fail + $totals.warn + $totals.error
    $fixable   = @($Findings | Where-Object { $_.AutoFixAvailable -and $_.Status -in @('Fail', 'Warning') })

    if ($attention -eq 0) {
        $headline = "All $total checks passing"
        $subline  = 'Nothing needs attention in this run.'
    }
    else {
        $verb = if ($attention -eq 1) { 'check needs' } else { 'checks need' }
        $headline = "$attention of $total $verb attention"
        $subline  = "$($totals.pass) passing."
    }

    # Every implement command on the page shares this prefix.
    $implCmd = 'Invoke-ADHardening -Mode Implement'
    if (-not [string]::IsNullOrWhiteSpace($RunPath)) {
        $resolved = try { (Resolve-Path -LiteralPath $RunPath -ErrorAction Stop).Path } catch { $RunPath }
        $quoted = if ($resolved -match '\s') { "'$resolved'" } else { $resolved }
        $implCmd = "$implCmd -ReportPath $quoted"
    }

    $sorted = $Findings | Sort-Object @{ Expression = { $statusPrio[[string]$_.Status] } }, CheckId

    $records = foreach ($f in $sorted) {
        $sk    = $statusKey[[string]$f.Status];  if (-not $sk) { $sk = 'na' }
        $sig   = $statusSig[[string]$f.Status];  if (-not $sig) { $sig = 'quiet' }
        $sword = $statusWord[[string]$f.Status]; if (-not $sword) { $sword = [string]$f.Status }
        $prio  = $statusPrio[[string]$f.Status]; if ($null -eq $prio) { $prio = 4 }

        $ev        = ConvertTo-ADHEvidenceMap -Evidence $f.Evidence
        $railKeys  = @('AuditMethod', 'Limitations', 'RequiresElevation', 'ElevationContext')
        $method    = [string]$ev['AuditMethod']
        $limits    = [string]$ev['Limitations']
        $elevCtx   = [string]$ev['ElevationContext']
        $needsElev = $ev['RequiresElevation']

        $rail = @()
        if (-not [string]::IsNullOrWhiteSpace($method)) {
            $rail += "<div class=""rail-row""><span class=""rail-k"">how this was checked</span><span class=""rail-v"">$(Format-ADHHtmlText $method)</span></div>"
        }
        if (-not [string]::IsNullOrWhiteSpace($limits)) {
            $rail += "<div class=""rail-row""><span class=""rail-k"">what this does not prove</span><span class=""rail-v"">$(Format-ADHHtmlText $limits)</span></div>"
        }
        if ($null -ne $needsElev) {
            $elevText = if ($needsElev) { 'Yes' } else { 'No' }
            if (-not [string]::IsNullOrWhiteSpace($elevCtx)) { $elevText = "$elevText &#183; $(Format-ADHHtmlText $elevCtx '')" }
            $rail += "<div class=""rail-row""><span class=""rail-k"">needs elevation</span><span class=""rail-v"">$elevText</span></div>"
        }
        $railHtml = if ($rail) { "<div class=""rail"">$($rail -join '')</div>" } else { '' }

        $affected = @($f.AffectedObjects | Where-Object { $_ })
        $affectedHtml = ''
        if ($affected.Count) {
            $objs = -join ($affected | ForEach-Object { "<li>$(Format-ADHHtmlText $_ '')</li>" })
            $affectedHtml = @"
<section class="block">
  <h3 class="block-h">Affected objects <span class="block-n">$($affected.Count)</span></h3>
  <ul class="objs">$objs</ul>
</section>
"@
        }

        $remediationHtml = ''
        if (-not [string]::IsNullOrWhiteSpace([string]$f.RemediationSteps)) {
            $remediationHtml = @"
<section class="block">
  <h3 class="block-h">Remediation</h3>
  <div class="steps">$(Format-ADHHtmlText $f.RemediationSteps '')</div>
</section>
"@
        }

        $fixHtml = ''
        if ($f.AutoFixAvailable -and $f.Status -in @('Fail', 'Warning')) {
            $cmd = "$implCmd -IncludeCheckIds $($f.CheckId)"
            $fixHtml = @"
<div class="fix">
  <span class="fix-tag">Automated fix</span>
  <code class="fix-cmd">$(Format-ADHHtmlText $cmd '')</code>
  <button type="button" class="copy" data-copy="$(Format-ADHHtmlText $cmd '')">Copy command</button>
</div>
"@
        }

        $restKeys = @($ev.Keys | Where-Object { $railKeys -notcontains $_ } | Sort-Object)
        $evidenceHtml = ''
        if ($restKeys.Count) {
            $rest = @{}
            foreach ($k in $restKeys) { $rest[$k] = $ev[$k] }
            $json = ($rest | ConvertTo-Json -Depth 10)
            $evidenceHtml = @"
<details class="drop">
  <summary><span class="drop-t">Evidence</span><span class="drop-n">$($restKeys.Count) keys</span></summary>
  <pre class="code">$(Format-ADHHtmlText $json '')</pre>
</details>
"@
        }

        $refs = @($f.References | Where-Object { $_ })
        $refsHtml = ''
        if ($refs.Count) {
            $items = -join ($refs | ForEach-Object {
                $enc = [System.Net.WebUtility]::HtmlEncode([string]$_)
                if ($_ -match '^https?://') { "<li><a href=""$enc"" target=""_blank"" rel=""noopener noreferrer"">$enc</a></li>" }
                else { "<li>$enc</li>" }
            })
            $refsHtml = @"
<details class="drop">
  <summary><span class="drop-t">References</span><span class="drop-n">$($refs.Count)</span></summary>
  <ul class="refs">$items</ul>
</details>
"@
        }

        $drops = "$evidenceHtml$refsHtml"
        $dropsHtml = if ($drops) { "<div class=""drops"">$drops</div>" } else { '' }

        @"
<details class="rec" id="$($f.CheckId)" data-sig="$sig" data-filter="$sk" data-prio="$prio" data-id="$($f.CheckId)" data-cat="$(Format-ADHHtmlText $f.Category '')">
  <summary class="rec-sum">
    <span class="rec-id">$(Format-ADHHtmlText $f.CheckId '')</span>
    <span class="rec-state"><span class="dot"></span>$sword</span>
    <span class="rec-name">$(Format-ADHHtmlText $f.CheckName '')</span>
    <span class="rec-cat">$(Format-ADHHtmlText $f.Category '')</span>
  </summary>
  <div class="rec-body">
    <p class="rec-desc">$(Format-ADHHtmlText $f.Description '')</p>
    $railHtml
    $affectedHtml
    $remediationHtml
    $fixHtml
    $dropsHtml
  </div>
</details>
"@
    }

    # Name the checks rather than counting them, and offer the plain implement
    # command: with no -IncludeCheckIds it fixes every auto-fixable finding in
    # this audit, which is exactly the list named.
    $fixStrip = ''
    if ($fixable.Count) {
        $ids = @($fixable | Sort-Object CheckId | ForEach-Object { [string]$_.CheckId })
        $idList = if ($ids.Count -eq 1) { $ids[0] }
                  elseif ($ids.Count -eq 2) { $ids -join ' and ' }
                  else { ($ids[0..($ids.Count - 2)] -join ', ') + ' and ' + $ids[-1] }
        $lead = if ($ids.Count -eq 1) {
            "$idList has an automated fix. Review it below, then apply it:"
        } elseif ($ids.Count -eq 2) {
            "$idList have automated fixes. Review them below, then apply both:"
        } else {
            "$idList have automated fixes. Review them below, then apply all $($ids.Count):"
        }
        $fixStrip = @"
<div class="strip">
  <p class="strip-t">$(Format-ADHHtmlText $lead '')</p>
  <div class="strip-cmd">
    <code>$(Format-ADHHtmlText $implCmd '')</code>
    <button type="button" class="copy" data-copy="$(Format-ADHHtmlText $implCmd '')">Copy command</button>
  </div>
</div>
"@
    }

    $chipDefs = @(
        @{ k = 'fail';  sig = 'rose';   label = 'Fail';    n = $totals.fail  }
        @{ k = 'warn';  sig = 'brass';  label = 'Warning'; n = $totals.warn  }
        @{ k = 'error'; sig = 'violet'; label = 'Error';   n = $totals.error }
        @{ k = 'pass';  sig = 'jade';   label = 'Pass';    n = $totals.pass  }
        @{ k = 'na';    sig = 'quiet';  label = 'N/A';     n = $totals.na    }
    )
    $chipHtml = -join ($chipDefs | ForEach-Object {
        $dis = if ($_.n -eq 0) { ' disabled' } else { '' }
        "<button type=""button"" class=""chip"" data-filter=""$($_.k)"" data-sig=""$($_.sig)""$dis><span class=""dot""></span>$($_.label)<span class=""chip-n"">$($_.n)</span></button>"
    })

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
<title>Invoke-ADHardening audit - $(Format-ADHHtmlText $domain '')</title>
<script>$bootTheme</script>
<style>
$css
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <span class="brand">Invoke-ADHardening &#183; audit</span>
    <button type="button" class="theme" id="theme" aria-label="Switch to light theme">
      <span class="glyph" aria-hidden="true">&#9728;</span><span class="label">Light</span>
    </button>
  </header>

  <h1 class="domain">$(Format-ADHHtmlText $domain '')</h1>
  <p class="headline">$(Format-ADHHtmlText $headline '') <span class="quiet">$(Format-ADHHtmlText $subline '')</span></p>
  <p class="stamp">$(Format-ADHHtmlText $generated '')</p>

  $fixStrip

  <div class="controls">
    <button type="button" class="chip chip-all" data-filter="all" aria-pressed="true"><span class="dot"></span>All</button>
$chipHtml
    <span class="spacer"></span>
    <span class="readout" id="readout" data-noun="checks">$total checks</span>
    <button type="button" class="ghost-btn" id="expand" data-mode="expand">Expand all</button>
    <label class="sortwrap" for="sortby">Sort
      <select id="sortby">
        <option value="priority">Status</option>
        <option value="id">Check ID</option>
        <option value="category">Category</option>
      </select>
    </label>
  </div>

  <main class="records" id="records">
$($records -join "`n")
  </main>
  <p class="empty" id="empty" hidden>No checks match this filter.</p>

  <footer class="foot">
    <span>Reports stay local. No telemetry, no upload.</span>
    <span>Alongside: report.json &#183; report.csv &#183; findings.jsonl &#183; audit.log</span>
  </footer>
</div>

<script>
$js
</script>
</body>
</html>
"@
}
