function Write-ADHLog {
    <#
    .SYNOPSIS
        Centralized logger for Invoke-ADHardening.
    .DESCRIPTION
        Writes a timestamped line to audit.log. When a Finding is supplied,
        also appends its JSON to findings.jsonl. With -Console, mirrors the
        line to the host using a level-appropriate color.

        Requires $script:ADHLogPath to be set by the orchestrator before
        any check or fix runs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO','CHECK','PASS','FAIL','WARN','ERROR','FIX','DEBUG')]
        [string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [PSCustomObject]$Finding,
        [switch]$Console
    )

    if (-not $script:ADHLogPath) {
        Write-Warning "ADHLogPath not initialized. Call Initialize-ADHRun first."
        return
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $logLine   = "$timestamp [$Level] $Message"

    Add-Content -Path (Join-Path $script:ADHLogPath 'audit.log') -Value $logLine

    if ($Finding) {
        $jsonLine = $Finding | ConvertTo-Json -Compress -Depth 10
        Add-Content -Path (Join-Path $script:ADHLogPath 'findings.jsonl') -Value $jsonLine
    }

    if ($Console) {
        $color = switch ($Level) {
            'PASS'  { 'Green' }
            'FAIL'  { 'Red' }
            'WARN'  { 'Yellow' }
            'ERROR' { 'Magenta' }
            'FIX'   { 'Cyan' }
            default { 'Gray' }
        }
        Write-Host $logLine -ForegroundColor $color
    }
}
