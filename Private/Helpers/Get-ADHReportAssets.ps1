# Shared design system for the HTML reports.
#
# Both New-ADHHtmlReport (audit) and New-ADHImplementationReport (implement)
# render from these, so the two pages are one design rather than two that drift.
# Everything is inline - no external requests - so a report opens from a file://
# path on an air-gapped jump box.
#
# The page has no chart and shows no severity rating: status is the only signal,
# so the collapsed list of checks IS the overview. Each check is a <details> row
# that opens onto its detail, which means the whole domain fits on one screen and
# the page still works with JavaScript disabled.
#
# KEEP THIS FILE PURE ASCII. Windows PowerShell reads a BOM-less .ps1 as ANSI,
# so a literal non-ASCII glyph in the CSS/JS below reaches the browser as
# mojibake. Use \uXXXX in JS and &#NNN; in the calling HTML.
#
# Markup contract - a page using these assets emits:
#   #theme                     the light/dark toggle button (.glyph + .label)
#   #expand                    expand-all / collapse-all toggle (optional)
#   .chip[data-filter][data-sig]  status filter row; one has data-filter="all"
#   #sortby                    <select>; values order|priority|id|category
#   #records > details.rec[data-sig][data-filter][data-order][data-prio]
#                              [data-id][data-cat]
#   #readout[data-noun]        "N of M <noun>" counter
#   #empty                     the no-matches message
#   .copy[data-copy]           copy-to-clipboard buttons (optional)

function Format-ADHHtmlText {
    <#
    .SYNOPSIS
        HTML-encodes a value for safe interpolation into a report.
    .PARAMETER Text
        The value to encode. $null and empty render as the supplied fallback.
    .PARAMETER Fallback
        What to emit when Text is null/empty. Defaults to an em dash.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()][object]$Text,
        [string]$Fallback = '&#8212;'
    )
    $s = [string]$Text
    if ([string]::IsNullOrWhiteSpace($s)) { return $Fallback }
    [System.Net.WebUtility]::HtmlEncode($s)
}

function Get-ADHReportBootScript {
    <#
    .SYNOPSIS
        The pre-paint theme script, for the document <head>.
    .DESCRIPTION
        Applies the stored theme before first paint so a light-mode reader does
        not get a dark flash. Dark is the default, including when localStorage
        is unavailable - which it is in some browsers on file:// URLs.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    @'
try { var t = localStorage.getItem('adh-theme'); document.documentElement.setAttribute('data-theme', t === 'light' ? 'light' : 'dark'); } catch (e) {}
'@
}

function Get-ADHReportStyle {
    <#
    .SYNOPSIS
        The shared report stylesheet.
    .DESCRIPTION
        Dark (default) and light themes off a data-theme attribute on <html>.

        Colour carries exactly one dimension - state - through a --sig custom
        property set by a data-sig attribute, and never carries it alone: every
        state is spelled out in words beside its colour. Both ramps were
        validated for colour-vision separation and contrast against their own
        surfaces (OKLab deltaE across all pairs under simulated protanopia and
        deuteranopia, plus WCAG contrast).

        Mono is the interface voice - IDs, labels, counts, commands, DNs - and
        sans is reserved for prose, because everything this tool reports is an
        identifier.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    @'
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; }
[hidden] { display: none !important; }

:root {
  --f-mono: "Cascadia Mono", "Cascadia Code", Consolas, "SF Mono", Menlo, ui-monospace, monospace;
  --f-sans: "Segoe UI Variable Text", "Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;

  --ink:   #0B0F16;
  --slate: #141A24;
  --rise:  #1A2231;
  --rule:  #232C3B;
  --bone:  #DCE3ED;
  --body:  #AFBACA;
  --mute:  #8592A6;
  --dim:   #66748A;

  --jade:   #31D6B4;
  --brass:  #E8B14B;
  --rose:   #FF6274;
  --violet: #B48CFF;
  --quiet:  #5F6B80;

  --wash: 14%;
  --lift: none;
  --pagemax: 1080px;
}

:root[data-theme="light"] {
  --ink:   #E7EAF0;
  --slate: #FFFFFF;
  --rise:  #F3F5F9;
  --rule:  #D3D9E2;
  --bone:  #151A22;
  --body:  #3B4552;
  --mute:  #5A6575;
  --dim:   #798394;

  --jade:   #00697A;
  --brass:  #A25E00;
  --rose:   #C2185B;
  --violet: #6236B8;
  --quiet:  #8B94A2;

  --wash: 8%;
  --lift: 0 1px 2px rgba(16,24,40,.05), 0 10px 28px -18px rgba(16,24,40,.35);
}

[data-sig="jade"]   { --sig: var(--jade); }
[data-sig="brass"]  { --sig: var(--brass); }
[data-sig="rose"]   { --sig: var(--rose); }
[data-sig="violet"] { --sig: var(--violet); }
[data-sig="quiet"]  { --sig: var(--quiet); }

body {
  background: var(--ink);
  color: var(--bone);
  font-family: var(--f-sans);
  font-size: 16px;
  line-height: 1.6;
}

.wrap { max-width: var(--pagemax); margin: 0 auto; padding: 0 24px 96px; }

/* ---- masthead ------------------------------------------------------- */

.top {
  display: flex; align-items: flex-start; justify-content: space-between;
  gap: 24px; padding: 32px 0 0;
}
.brand {
  font-family: var(--f-mono); font-size: 11px; font-weight: 600;
  letter-spacing: .18em; text-transform: uppercase; color: var(--dim);
}
.theme {
  font-family: var(--f-mono); font-size: 11px; letter-spacing: .12em;
  text-transform: uppercase; color: var(--mute);
  background: transparent; border: 1px solid var(--rule); border-radius: 999px;
  padding: 7px 14px; cursor: pointer; white-space: nowrap;
  display: inline-flex; align-items: center; gap: 8px;
}
.theme:hover { color: var(--bone); border-color: var(--dim); }
.theme .glyph { font-size: 13px; line-height: 1; }

.domain {
  font-family: var(--f-mono); font-weight: 600;
  font-size: clamp(2rem, 7vw, 3.5rem); line-height: 1.02;
  letter-spacing: -.035em; margin: 22px 0 0; color: var(--bone);
  overflow-wrap: anywhere;
}
.headline {
  font-size: clamp(1.05rem, 2.4vw, 1.4rem); font-weight: 500;
  margin: 14px 0 0; color: var(--bone);
}
.headline .quiet { color: var(--mute); }
.stamp {
  font-family: var(--f-mono); font-size: 12px; color: var(--dim);
  letter-spacing: .04em; margin: 8px 0 0;
}
.stamp a { color: var(--mute); text-decoration: none; border-bottom: 1px solid var(--rule); }
.stamp a:hover { color: var(--bone); border-bottom-color: var(--dim); }

.notice {
  margin: 24px 0 0; padding: 14px 18px; border-radius: 10px;
  border: 1px solid var(--sig); background: var(--rise);
  font-family: var(--f-mono); font-size: 12px; letter-spacing: .06em;
  color: var(--bone); display: flex; flex-wrap: wrap; gap: 4px 12px; align-items: baseline;
}
.notice-k { color: var(--sig); font-weight: 600; letter-spacing: .14em; text-transform: uppercase; }

/* ---- next step ------------------------------------------------------ */

.strip {
  margin: 32px 0 0; padding: 18px 20px;
  background: var(--rise); border: 1px solid var(--rule); border-radius: 12px;
}
.strip-t { margin: 0 0 12px; font-size: 14px; color: var(--mute); }
.strip-cmd { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.strip-cmd code {
  font-family: var(--f-mono); font-size: 13px; color: var(--bone);
  background: var(--ink); border: 1px solid var(--rule); border-radius: 7px;
  padding: 8px 12px; overflow-wrap: anywhere;
}

.copy, .ghost-btn {
  font-family: var(--f-mono); font-size: 11px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--mute); cursor: pointer;
  background: transparent; border: 1px solid var(--rule); border-radius: 7px;
  padding: 8px 12px; white-space: nowrap;
}
.copy:hover, .ghost-btn:hover { color: var(--bone); border-color: var(--dim); }

/* ---- controls ------------------------------------------------------- */

.controls {
  position: sticky; top: 0; z-index: 10;
  display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
  margin: 40px 0 0; padding: 14px 0;
  background: var(--ink); border-bottom: 1px solid var(--rule);
}
.chip {
  font-family: var(--f-mono); font-size: 11px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--mute); cursor: pointer;
  background: transparent; border: 1px solid var(--rule); border-radius: 999px;
  padding: 7px 13px; display: inline-flex; align-items: center; gap: 8px;
}
.chip:hover:not([disabled]) { color: var(--bone); border-color: var(--dim); }
.chip[disabled] { opacity: .4; cursor: default; }
.chip[aria-pressed="true"] {
  color: var(--bone); border-color: var(--sig, var(--dim));
  background: color-mix(in srgb, var(--sig, var(--dim)) var(--wash), transparent);
}
.chip-n { font-variant-numeric: tabular-nums; color: var(--dim); }
.chip[aria-pressed="true"] .chip-n { color: var(--bone); }
.chip-all { --sig: var(--dim); }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--sig, var(--dim)); flex: none; }
.chip-all .dot { display: none; }

.spacer { flex: 1 1 auto; }
.sortwrap {
  display: inline-flex; align-items: center; gap: 8px;
  font-family: var(--f-mono); font-size: 11px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--dim);
  padding-left: 16px; border-left: 1px solid var(--rule);
}
.sortwrap select {
  font-family: var(--f-mono); font-size: 11px; letter-spacing: .08em;
  color: var(--bone); background: var(--rise);
  border: 1px solid var(--rule); border-radius: 7px; padding: 7px 10px; cursor: pointer;
}
.readout {
  font-family: var(--f-mono); font-size: 11px; letter-spacing: .08em;
  text-transform: uppercase; color: var(--dim); font-variant-numeric: tabular-nums;
}

/* ---- records: collapsed by default, open onto the detail ------------ */

.records { display: flex; flex-direction: column; gap: 8px; margin: 20px 0 0; }

.rec {
  background: var(--slate);
  border: 1px solid var(--rule); border-left: 3px solid var(--sig);
  border-radius: 3px 10px 10px 3px; box-shadow: var(--lift);
  scroll-margin-top: 76px;
}
.rec[open] { background: var(--slate); }

.rec-sum {
  cursor: pointer; list-style: none;
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 16px;
  padding: 15px 20px;
}
.rec-sum::-webkit-details-marker { display: none; }
.rec-sum::before {
  content: ">"; font-family: var(--f-mono); font-size: 12px; color: var(--dim);
  width: 10px; flex: none; align-self: center;
  transition: transform .16s ease, color .16s ease;
}
.rec[open] > .rec-sum::before { transform: rotate(90deg); color: var(--sig); }
.rec-sum:hover::before { color: var(--sig); }
.rec-sum:hover .rec-name { color: var(--sig); }

.rec-id {
  font-family: var(--f-mono); font-size: 12px; font-weight: 600;
  letter-spacing: .08em; color: var(--bone); flex: none;
}
.rec-state {
  font-family: var(--f-mono); font-size: 11px; font-weight: 600;
  letter-spacing: .14em; text-transform: uppercase; color: var(--sig);
  display: inline-flex; align-items: center; gap: 7px; flex: none;
  min-width: 96px;
}
.rec-name {
  font-size: 16px; font-weight: 600; color: var(--bone);
  flex: 1 1 260px; min-width: 0; transition: color .16s ease;
}
.rec-cat {
  font-family: var(--f-mono); font-size: 10px; letter-spacing: .13em;
  text-transform: uppercase; color: var(--dim); flex: none; margin-left: auto;
}

.rec-body { padding: 0 20px 20px 46px; }
.rec-desc { margin: 0; color: var(--body); max-width: 74ch; }

/* before -> after transition (implement report) */
.flow {
  display: inline-flex; flex-wrap: wrap; align-items: center; gap: 10px;
  margin: 16px 0 0; padding: 10px 14px;
  background: var(--rise); border: 1px solid var(--rule); border-radius: 10px;
  font-family: var(--f-mono); font-size: 12px; letter-spacing: .1em; text-transform: uppercase;
}
.flow-k { color: var(--dim); }
.flow-a { color: var(--mute); }
.flow-arrow { color: var(--dim); }
.flow-b { color: var(--sig); font-weight: 600; }
.flow-ok { color: var(--jade); font-weight: 600; }
.flow-no { color: var(--dim); }

.rail { margin: 18px 0 0; border-top: 1px solid var(--rule); padding-top: 14px; display: grid; gap: 10px; }
.rail-row { display: grid; grid-template-columns: 190px 1fr; gap: 16px; align-items: baseline; }
.rail-k {
  font-family: var(--f-mono); font-size: 10px; letter-spacing: .13em;
  text-transform: uppercase; color: var(--dim);
}
.rail-v { font-size: 13.5px; color: var(--body); max-width: 82ch; }
.rail-v code { font-family: var(--f-mono); font-size: 12.5px; color: var(--bone); }

.block { margin: 20px 0 0; }
.block-h {
  font-family: var(--f-mono); font-size: 10px; letter-spacing: .14em;
  text-transform: uppercase; color: var(--dim); font-weight: 600;
  margin: 0 0 9px; display: flex; align-items: center; gap: 8px;
}
.block-n { color: var(--sig); font-variant-numeric: tabular-nums; }

.objs { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 6px; }
.objs li {
  font-family: var(--f-mono); font-size: 12px; color: var(--bone);
  background: var(--rise); border: 1px solid var(--rule); border-radius: 6px;
  padding: 5px 9px; overflow-wrap: anywhere;
}

.steps {
  white-space: pre-wrap; font-size: 14px; color: var(--bone);
  background: var(--rise); border: 1px solid var(--rule);
  border-radius: 10px; padding: 14px 16px; max-width: 92ch; overflow-wrap: anywhere;
}

.fix {
  margin: 18px 0 0; display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
  padding: 12px 14px; border: 1px dashed var(--rule); border-radius: 10px;
}
.fix-tag {
  font-family: var(--f-mono); font-size: 10px; letter-spacing: .14em;
  text-transform: uppercase; color: var(--sig); font-weight: 600;
}
.fix-cmd { font-family: var(--f-mono); font-size: 13px; color: var(--bone); overflow-wrap: anywhere; }

.drops { margin: 18px 0 0; border-top: 1px solid var(--rule); }
.drop { border-bottom: 1px solid var(--rule); }
.drop summary {
  cursor: pointer; list-style: none; padding: 11px 0;
  display: flex; align-items: center; gap: 10px;
}
.drop summary::-webkit-details-marker { display: none; }
.drop summary::before {
  content: "+"; font-family: var(--f-mono); font-size: 13px; color: var(--dim);
  width: 12px; text-align: center;
}
.drop[open] summary::before { content: "\2212"; }
.drop summary:hover .drop-t { color: var(--bone); }
.drop-t {
  font-family: var(--f-mono); font-size: 10px; letter-spacing: .14em;
  text-transform: uppercase; color: var(--mute); font-weight: 600;
}
.drop-n { font-family: var(--f-mono); font-size: 10px; letter-spacing: .1em; color: var(--dim); }

.code {
  font-family: var(--f-mono); font-size: 12px; line-height: 1.65;
  background: var(--ink); border: 1px solid var(--rule); border-radius: 10px;
  padding: 14px 16px; margin: 0 0 14px; color: var(--mute);
  max-height: 380px; overflow: auto; white-space: pre; tab-size: 2;
}
.refs { list-style: none; margin: 0 0 14px; padding: 0; display: grid; gap: 6px; }
.refs li { font-family: var(--f-mono); font-size: 12px; overflow-wrap: anywhere; color: var(--mute); }
.refs a { color: var(--bone); text-decoration: none; border-bottom: 1px solid var(--rule); }
.refs a:hover { border-bottom-color: var(--sig); }

.empty {
  text-align: center; padding: 56px 20px; color: var(--mute);
  border: 1px dashed var(--rule); border-radius: 12px; margin: 20px 0 0;
}

.foot {
  margin: 56px 0 0; padding-top: 20px; border-top: 1px solid var(--rule);
  font-family: var(--f-mono); font-size: 11px; letter-spacing: .06em; color: var(--dim);
  display: flex; flex-wrap: wrap; gap: 6px 20px;
}
.foot a { color: var(--mute); text-decoration: none; border-bottom: 1px solid var(--rule); }
.foot a:hover { color: var(--bone); }

:focus-visible { outline: 2px solid var(--sig, var(--dim)); outline-offset: 2px; }

/* ---- responsive ----------------------------------------------------- */

@media (max-width: 720px) {
  .wrap { padding: 0 16px 64px; }
  .rec-sum { padding: 14px 16px; gap: 4px 12px; }
  .rec-name { flex-basis: 100%; }
  .rec-cat { margin-left: 0; }
  .rec-body { padding: 0 16px 18px 16px; }
  .rail-row { grid-template-columns: 1fr; gap: 3px; }
  .controls { gap: 8px; }
  .sortwrap { padding-left: 0; border-left: 0; }
}

/* ---- motion --------------------------------------------------------- */

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; animation-delay: 0ms !important; transition-duration: .001ms !important; }
}

/* ---- print ---------------------------------------------------------- */

@media print {
  .controls, .theme, .copy, .ghost-btn { display: none !important; }
  body { background: #fff; color: #111; }
  .rec { break-inside: avoid; box-shadow: none; }
  .rec-body { display: block !important; }
  .drop[open] .code { max-height: none; }
}
'@
}

function Get-ADHReportScript {
    <#
    .SYNOPSIS
        The shared report behaviour: theme toggle, filter, sort, expand, copy.
    .DESCRIPTION
        Every block guards for its elements being absent, so a page can adopt
        only the parts it needs. Records are rendered server-side and merely
        reordered here, and disclosure is native <details>, so the report still
        reads with JavaScript disabled.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    @'
(function () {
  var root = document.documentElement;
  function attr(el, n) { return el.getAttribute(n) || ''; }
  function all(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }

  /* Glyphs stay as \u escapes: this JS is embedded in a .ps1 that Windows
     PowerShell reads as ANSI when it has no BOM, so any literal non-ASCII byte
     here reaches the browser as mojibake. */
  var SUN = '\u2600', MOON = '\u263D';

  /* theme ------------------------------------------------------------- */
  var btn = document.getElementById('theme');
  if (btn) {
    var setTheme = function (t) {
      root.setAttribute('data-theme', t);
      btn.querySelector('.glyph').textContent = t === 'dark' ? SUN : MOON;
      btn.querySelector('.label').textContent = t === 'dark' ? 'Light' : 'Dark';
      btn.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
      try { localStorage.setItem('adh-theme', t); } catch (e) {}
    };
    setTheme(root.getAttribute('data-theme') === 'light' ? 'light' : 'dark');
    btn.addEventListener('click', function () {
      setTheme(root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });
  }

  /* filter, sort, expand ---------------------------------------------- */
  var list = document.getElementById('records');
  if (!list) { return; }

  var recs = Array.prototype.slice.call(list.querySelectorAll('.rec'));
  var chips = all('.chip');
  var sortSel = document.getElementById('sortby');
  var readout = document.getElementById('readout');
  var empty = document.getElementById('empty');
  var expandBtn = document.getElementById('expand');
  var noun = readout ? (attr(readout, 'data-noun') || 'items') : 'items';
  var filter = 'all';

  function visible() { return recs.filter(function (r) { return !r.hidden; }); }

  function syncExpandLabel() {
    if (!expandBtn) { return; }
    var shown = visible();
    var allOpen = shown.length > 0 && shown.every(function (r) { return r.open; });
    expandBtn.textContent = allOpen ? 'Collapse all' : 'Expand all';
    expandBtn.setAttribute('data-mode', allOpen ? 'collapse' : 'expand');
  }

  function applyFilter() {
    var shown = 0;
    recs.forEach(function (r) {
      var ok = filter === 'all' || attr(r, 'data-filter') === filter;
      r.hidden = !ok;
      if (ok) { shown++; }
    });
    if (readout) {
      readout.textContent = (shown === recs.length ? recs.length : shown + ' of ' + recs.length) + ' ' + noun;
    }
    if (empty) { empty.hidden = shown > 0; }
    chips.forEach(function (c) {
      c.setAttribute('aria-pressed', String(attr(c, 'data-filter') === filter));
    });
    syncExpandLabel();
  }

  function applySort() {
    var key = sortSel ? sortSel.value : 'order';
    recs.slice().sort(function (a, b) {
      var byId = attr(a, 'data-id').localeCompare(attr(b, 'data-id'));
      if (key === 'id') { return byId; }
      if (key === 'order') { return attr(a, 'data-order') - attr(b, 'data-order'); }
      if (key === 'category') { return attr(a, 'data-cat').localeCompare(attr(b, 'data-cat')) || byId; }
      return (attr(a, 'data-prio') - attr(b, 'data-prio')) || byId;
    }).forEach(function (r) { list.appendChild(r); });
  }

  chips.forEach(function (c) {
    c.addEventListener('click', function () {
      if (c.hasAttribute('disabled')) { return; }
      var next = attr(c, 'data-filter');
      filter = (filter === next && next !== 'all') ? 'all' : next;
      applyFilter();
    });
  });
  if (sortSel) { sortSel.addEventListener('change', applySort); }
  if (expandBtn) {
    expandBtn.addEventListener('click', function () {
      var open = attr(expandBtn, 'data-mode') !== 'collapse';
      visible().forEach(function (r) { r.open = open; });
      syncExpandLabel();
    });
  }
  recs.forEach(function (r) { r.addEventListener('toggle', syncExpandLabel); });
  applyFilter();

  /* a link to a collapsed check should open it ------------------------ */
  function openTarget() {
    if (!window.location.hash) { return; }
    var t = document.getElementById(window.location.hash.slice(1));
    if (t && t.classList.contains('rec')) { t.open = true; syncExpandLabel(); }
  }
  window.addEventListener('hashchange', openTarget);
  openTarget();

  /* copy -------------------------------------------------------------- */
  function flash(b) {
    var was = b.textContent;
    b.textContent = 'Copied';
    setTimeout(function () { b.textContent = was; }, 1400);
  }
  function fallbackCopy(text, b) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); flash(b); } catch (e) {}
    document.body.removeChild(ta);
  }
  all('.copy').forEach(function (b) {
    b.addEventListener('click', function () {
      var text = attr(b, 'data-copy');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { flash(b); }, function () { fallbackCopy(text, b); });
      } else {
        fallbackCopy(text, b);
      }
    });
  });
}());
'@
}
