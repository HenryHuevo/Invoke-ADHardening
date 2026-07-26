function Set-MachineAccountQuota {
    <#
    .SYNOPSIS
        ADH-002 fix - sets the domain's ms-DS-MachineAccountQuota to 0.
    .DESCRIPTION
        This is a domain object modification, not a GPO change. After this
        runs, standard authenticated users can no longer join machines to
        the domain - your provisioning workflow MUST use a delegated admin
        or service account.

        Captures before/after state to changes.jsonl.
    .PARAMETER NewValue
        Target value. Defaults to 0. Exposed for the rare environment that
        wants a non-zero (but non-default) value.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateRange(0, 2147483647)]
        [int]$NewValue = 0
    )

    $changeRecord = [PSCustomObject]@{
        CheckId      = 'ADH-002'
        FixFunction  = 'Set-MachineAccountQuota'
        Timestamp    = [DateTime]::UtcNow
        BeforeState  = $null
        AfterState   = $null
        Success      = $false
        ErrorMessage = $null
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $domainDn = $domain.DistinguishedName
        $current = (Get-ADObject -Identity $domainDn `
            -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop).'ms-DS-MachineAccountQuota'

        $changeRecord.BeforeState = @{
            DomainDN                 = $domainDn
            MachineAccountQuotaValue = $current
        }

        if ($current -eq $NewValue) {
            Write-ADHLog -Level INFO -Message "ADH-002 fix skipped: already $NewValue" -Console
            $changeRecord.AfterState = $changeRecord.BeforeState
            $changeRecord.Success = $true
            return $changeRecord
        }

        Write-Host ''
        Write-Host '  WARNING: Setting ms-DS-MachineAccountQuota = 0 prevents non-admin users' -ForegroundColor Yellow
        Write-Host '  from joining machines to the domain. Ensure your provisioning workflow' -ForegroundColor Yellow
        Write-Host '  uses a delegated admin or dedicated service account before applying.' -ForegroundColor Yellow
        Write-Host ''

        if (-not $PSCmdlet.ShouldProcess(
            "Domain object '$domainDn'",
            "Set ms-DS-MachineAccountQuota from $current to $NewValue")) {
            return $changeRecord
        }

        Write-ADHLog -Level FIX -Message "Setting ms-DS-MachineAccountQuota=$NewValue on $domainDn" -Console
        Set-ADDomain -Identity $domain -Replace @{ 'ms-DS-MachineAccountQuota' = $NewValue } -ErrorAction Stop

        $verify = (Get-ADObject -Identity $domainDn `
            -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop).'ms-DS-MachineAccountQuota'

        $changeRecord.AfterState = @{
            DomainDN                 = $domainDn
            MachineAccountQuotaValue = $verify
        }
        $changeRecord.Success = ($verify -eq $NewValue)

        if ($changeRecord.Success) {
            Write-ADHLog -Level FIX -Message "ADH-002 Machine Account Quota - FIX applied (was $current, now $verify)" -Console
        } else {
            Write-ADHLog -Level ERROR -Message "ADH-002 fix verify failed: expected $NewValue, got $verify" -Console
        }
    }
    catch {
        $changeRecord.ErrorMessage = $_.Exception.Message
        Write-ADHLog -Level ERROR -Message "ADH-002 fix failed: $($_.Exception.Message)" -Console
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
