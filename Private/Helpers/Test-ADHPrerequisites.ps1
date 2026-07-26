function Test-ADHPrerequisites {
    <#
    .SYNOPSIS
        Verifies the runtime can perform an Invoke-ADHardening audit.
    .DESCRIPTION
        Confirms the ActiveDirectory and GroupPolicy modules are available,
        that the AD domain is reachable, and that the current principal can
        read AD. Returns $true on success, $false on any failure (with
        diagnostic INFO/ERROR lines in audit.log).
    #>
    [CmdletBinding()]
    param()

    $ok = $true

    foreach ($mod in @('ActiveDirectory','GroupPolicy')) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-ADHLog -Level ERROR -Message "Required module not installed: $mod (install RSAT)" -Console
            $ok = $false
        } else {
            try {
                Import-Module $mod -ErrorAction Stop
                Write-ADHLog -Level INFO -Message "Module loaded: $mod"
            } catch {
                Write-ADHLog -Level ERROR -Message "Failed to import $mod : $($_.Exception.Message)" -Console
                $ok = $false
            }
        }
    }

    if (-not $ok) { return $false }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
        Write-ADHLog -Level INFO -Message "Domain: $($domain.DNSRoot)   Forest: $($forest.Name)" -Console
    } catch {
        Write-ADHLog -Level ERROR -Message "Cannot reach AD: $($_.Exception.Message)" -Console
        return $false
    }

    try {
        $whoami = "$env:USERDOMAIN\$env:USERNAME"
        $runAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
        Write-ADHLog -Level INFO -Message "Run by: $whoami        Run at: $runAt" -Console
    } catch {
        Write-ADHLog -Level WARN -Message "Could not determine current principal: $($_.Exception.Message)" -Console
    }

    return $true
}
