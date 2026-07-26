function Set-LLMNRDisabled {
    <#
    .SYNOPSIS
        ADH-001 fix - creates/updates the Invoke-ADHardening Hardening GPO
        to enable the "Turn off multicast name resolution" policy (disable LLMNR).
    .DESCRIPTION
        Configures the Administrative Template
          Computer Configuration > Policies > Administrative Templates >
          Network > DNS Client > "Turn off multicast name resolution" = Enabled
        which sets HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0.

        Unlike the SMB/LDAP signing fixes (which configure Security Options),
        this is a genuine Administrative Template: it has no Security-Option
        form and is natively stored in registry.pol. Set-GPRegistryValue IS the
        canonical, in-box way to set an Administrative Template, and GPMC renders
        the result as the named "Turn off multicast name resolution" policy
        (verified - not an "Extra Registry Setting"). So this fix correctly
        stays on Set-GPRegistryValue.
    .PARAMETER GpoName
        Name of the GPO to create or update. Defaults to
        'Invoke-ADHardening Hardening'.
    .PARAMETER LinkAtDomainRoot
        Also link the GPO at the domain root if not already linked.
    .NOTES
        Emits a change record (before/after state) to changes.jsonl.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$GpoName = 'Invoke-ADHardening Hardening',
        [switch]$LinkAtDomainRoot
    )

    $changeRecord = [PSCustomObject]@{
        CheckId      = 'ADH-001'
        FixFunction  = 'Set-LLMNRDisabled'
        Timestamp    = [DateTime]::UtcNow
        BeforeState  = $null
        AfterState   = $null
        Success      = $false
        ErrorMessage = $null
    }

    try {
        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        $changeRecord.BeforeState = if ($existingGpo) {
            @{
                GpoExists       = $true
                GpoId           = $existingGpo.Id
                EnableMulticast = (Get-GPRegistryValue -Guid $existingGpo.Id `
                    -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                    -ValueName 'EnableMulticast' -ErrorAction SilentlyContinue).Value
            }
        } else { @{ GpoExists = $false } }

        if (-not $PSCmdlet.ShouldProcess(
            "Domain GPO '$GpoName'",
            "Create/update GPO and set EnableMulticast=0 (disable LLMNR)")) {
            return $changeRecord
        }

        if (-not $existingGpo) {
            Write-ADHLog -Level FIX -Message "Creating GPO: $GpoName" -Console
            $gpo = New-GPO -Name $GpoName -Comment 'Created by Invoke-ADHardening - AD hardening settings'
        } else { $gpo = $existingGpo }

        Write-ADHLog -Level FIX -Message 'Setting EnableMulticast=0 in GPO' -Console
        Set-GPRegistryValue `
            -Guid $gpo.Id `
            -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
            -ValueName 'EnableMulticast' `
            -Type DWord `
            -Value 0 | Out-Null

        if ($LinkAtDomainRoot) {
            $domainDn = (Get-ADDomain).DistinguishedName
            $existingLink = Get-GPInheritance -Target $domainDn |
                Select-Object -ExpandProperty GpoLinks |
                Where-Object { $_.GpoId -eq $gpo.Id }

            if (-not $existingLink) {
                Write-ADHLog -Level FIX -Message "Linking GPO at domain root: $domainDn" -Console
                New-GPLink -Guid $gpo.Id -Target $domainDn -LinkEnabled Yes | Out-Null
            }
        }

        $changeRecord.AfterState = @{
            GpoExists       = $true
            GpoId           = $gpo.Id
            EnableMulticast = 0
            LinkedAtRoot    = [bool]$LinkAtDomainRoot
        }
        $changeRecord.Success = $true

        Write-ADHLog -Level FIX -Message 'ADH-001 LLMNR Disabled - FIX applied successfully' -Console
    }
    catch {
        $changeRecord.ErrorMessage = $_.Exception.Message
        Write-ADHLog -Level ERROR -Message "ADH-001 fix failed: $($_.Exception.Message)" -Console
        throw
    }
    finally {
        if ($script:ADHLogPath) {
            $changeRecord | ConvertTo-Json -Compress -Depth 10 |
                Add-Content -Path (Join-Path $script:ADHLogPath 'changes.jsonl')
        }
    }

    return $changeRecord
}
