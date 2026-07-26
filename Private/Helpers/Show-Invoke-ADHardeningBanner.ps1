function Show-Invoke-ADHardeningBanner {
    <#
    .SYNOPSIS
        Prints the Invoke-ADHardening banner, credits, and disclaimer, then
        waits for the operator to press Enter (Ctrl-C aborts).
    .DESCRIPTION
        Suppress via the orchestrator's -NoBanner switch. Module version
        is pulled from the manifest at module-import time.
    #>
    [CmdletBinding()]
    param()

    $version = $script:ADHModuleVersion
    if (-not $version) { $version = 'dev' }

    $banner = @"

================================================================
  Invoke-ADHardening v$version - AD Hardening Audit
  Standing on the shoulders of: PingCastle (Vincent Le Toux),
  Purple Knight (Semperis), Locksmith (Jake Hildreth),
  Certify/Certipy (SpecterOps / Oliver Lyak), NetExec, Impacket,
  BloodHound, and the broader AD security community.
================================================================

  This tool is read-only in Audit mode. Implementation mode
  prompts before each change. Test in a lab first. You are
  responsible for your environment.

  Press Enter to continue, Ctrl-C to abort.
"@

    Write-Host $banner -ForegroundColor Cyan
    [void](Read-Host)
}
