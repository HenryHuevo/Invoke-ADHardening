function Test-LLMNR {
    <#
    .SYNOPSIS
        ADH-001 - Verifies LLMNR is disabled by GPO.
    .DESCRIPTION
        Iterates every GPO in the domain, looking for one that sets
        HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0
        and is linked & enabled somewhere. Reports Pass when at least one
        matching, linked GPO exists; Fail otherwise.
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-001 LLMNR Disabled - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-001'
        CheckName  = 'LLMNR Disabled'
        Category   = 'Legacy Protocols'
        Severity   = 'High'
        References = @(
            'https://learn.microsoft.com/en-us/windows-server/networking/dns/deploy/disable-llmnr',
            'MITRE ATT&CK T1557.001'
        )
    }

    try {
        $allGpos = Get-GPO -All -ErrorAction Stop
        $matchingGpos = @()

        foreach ($gpo in $allGpos) {
            try {
                $regValue = Get-GPRegistryValue `
                    -Guid $gpo.Id `
                    -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                    -ValueName 'EnableMulticast' `
                    -ErrorAction Stop

                if ($regValue.Value -eq 0) {
                    [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
                    $linksEnabled = $report.GPO.LinksTo |
                        Where-Object { $_.Enabled -eq 'true' } |
                        Select-Object -ExpandProperty SOMPath

                    if ($linksEnabled) {
                        $matchingGpos += [PSCustomObject]@{
                            Name     = $gpo.DisplayName
                            Id       = $gpo.Id
                            LinkedTo = $linksEnabled
                        }
                    }
                }
            }
            catch [System.ArgumentException] { continue }
        }

        $auditCtx = @{
            AuditMethod       = 'GPO registry-policy read (Get-GPRegistryValue + Get-GPOReport)'
            RequiresElevation = $false
            Limitations       = 'GPO inspection proves the policy exists, not that every host has applied it. A network probe (Responder analyze mode) would prove behaviour; an opt-in on-the-wire probe is on the project roadmap.'
        }

        if ($matchingGpos.Count -gt 0) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description "LLMNR is disabled via GPO ($($matchingGpos.Count) matching GPO(s) linked)." `
                -Evidence ($auditCtx + @{ MatchingGPOs = $matchingGpos }) `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-001 LLMNR Disabled - PASS' -Console
        }
        else {
            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description 'No linked GPO disables LLMNR. Hosts will respond to LLMNR poisoning attacks.' `
                -Evidence $auditCtx `
                -RemediationSteps 'Create a GPO that sets HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0 (REG_DWORD) and link it at the domain level.' `
                -AutoFixAvailable $true `
                -FixFunction 'Set-LLMNRDisabled'

            Write-ADHLog -Level FAIL -Message 'ADH-001 LLMNR Disabled - FAIL' -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-001 LLMNR Disabled - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
