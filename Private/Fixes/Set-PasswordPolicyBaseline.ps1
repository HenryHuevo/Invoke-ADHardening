function Set-PasswordPolicyBaseline {
    <#
    .SYNOPSIS
        ADH-009 fix - applies a hardening account-policy baseline via the
        Invoke-ADHardening Hardening GPO, linked and ENFORCED at the domain root.
    .DESCRIPTION
        Writes the baseline into the dedicated 'Invoke-ADHardening Hardening' GPO
        as named Account Policy settings ([System Access] in GptTmpl.inf), then
        links that GPO at the domain root and marks the link Enforced. The
        Default Domain Password Policy is never modified in place
        (Set-ADDefaultDomainPasswordPolicy is deliberately not used).

        Two reasons:
          * Separation / cleanup - the entire hardening footprint lives in one
            auditable GPO. Rollback is "unlink/delete the GPO", not "replay
            captured Default-Domain-Policy values".
          * Convention - matches every other broad-scope fix (ADH-001/003/004/005)
            which never touch the Default Domain Policy.

        Domain account policy ONLY takes effect from a GPO linked at the domain
        root (account policy in an OU-linked GPO sets the local SAM of member
        machines, not domain accounts). Enforced makes it win over the Default
        Domain Policy regardless of link order. Both are therefore mandatory and
        applied unconditionally here.

        Baseline applied (overrideable via parameters):
          MinPasswordLength        = 15
          LockoutThreshold         = 5
          LockoutDuration          = 15 minutes
          LockoutObservationWindow = 15 minutes
          ComplexityEnabled        = $true
          MaxPasswordAge           = 0 (never expire)

        MaxPasswordAge of 0 (never expire) with a strong minimum length is the
        NIST SP 800-63B posture: don't force periodic rotation. In the security
        template this is encoded as MaximumPasswordAge = -1 (handled below).

        WARNING: enabling complexity / raising minimum length applies to new and
        changed passwords from the next GP refresh on. Existing passwords are not
        retroactively invalidated, but the next change must meet the baseline.
        The confirmation gate (ShouldProcess + interactive Read-Host) reflects the
        domain-wide blast radius.
    .PARAMETER MinPasswordLength
        Minimum password length to enforce. Default 15.
    .PARAMETER LockoutThreshold
        Bad-logon attempts before lockout. Default 5.
    .PARAMETER LockoutDurationMinutes
        Lockout duration, minutes. Default 15.
    .PARAMETER LockoutObservationMinutes
        Reset-lockout-counter window, minutes. Default 15.
    .PARAMETER MaxPasswordAgeDays
        Maximum password age, days. 0 = never expire (the default, encoded as
        MaximumPasswordAge = -1 in the GPO). Values >0 are written as-is.
    .PARAMETER GpoName
        GPO to create/update. Defaults to 'Invoke-ADHardening Hardening' - the
        same GPO used by other broad-scope hardening fixes.
    .PARAMETER IAcknowledgeThisAffectsAllUsers
        Bypass the interactive typed-confirmation gate (for non-interactive use).
    .OUTPUTS
        changeRecord PSCustomObject (also appended to changes.jsonl).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateRange(8,128)]
        [int]$MinPasswordLength = 15,
        [ValidateRange(0,99)]
        [int]$LockoutThreshold = 5,
        [int]$LockoutDurationMinutes = 15,
        [int]$LockoutObservationMinutes = 15,
        [ValidateRange(0,999)]
        [int]$MaxPasswordAgeDays = 0,
        [string]$GpoName = 'Invoke-ADHardening Hardening',
        [switch]$IAcknowledgeThisAffectsAllUsers
    )

    $changeRecord = [PSCustomObject]@{
        CheckId      = 'ADH-009'
        FixFunction  = 'Set-PasswordPolicyBaseline'
        Timestamp    = [DateTime]::UtcNow
        BeforeState  = $null
        AfterState   = $null
        Success      = $false
        ErrorMessage = $null
    }

    # [System Access] encoding: MaximumPasswordAge = -1 means "passwords never
    # expire" (the GUI's "0 days"). 0 is not a valid never-expire value in the
    # security template, so translate the operator-facing 0 to -1.
    $maxAgeInf = if ($MaxPasswordAgeDays -le 0) { -1 } else { $MaxPasswordAgeDays }
    $maxAgeDisplay = if ($maxAgeInf -eq -1) { 'never expire' } else { "$MaxPasswordAgeDays days" }

    try {
        # Effective domain policy before (read-only; for the change record).
        $current = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        $changeRecord.BeforeState = @{
            Source                  = 'Effective domain policy (pre-change)'
            MinPasswordLength       = $current.MinPasswordLength
            LockoutThreshold        = $current.LockoutThreshold
            LockoutDurationMinutes  = $current.LockoutDuration.TotalMinutes
            LockoutObsMinutes       = $current.LockoutObservationWindow.TotalMinutes
            MaxPasswordAgeDays      = $current.MaxPasswordAge.TotalDays
            ComplexityEnabled       = $current.ComplexityEnabled
        }

        Write-Host ''
        Write-Host '  =============================================================' -ForegroundColor Yellow
        Write-Host '  WARNING - ADH-009 Password Policy Baseline' -ForegroundColor Yellow
        Write-Host '  =============================================================' -ForegroundColor Yellow
        Write-Host "  About to write account policy into the GPO '$GpoName'," -ForegroundColor Yellow
        Write-Host '  linked and ENFORCED at the domain root. This becomes the' -ForegroundColor Yellow
        Write-Host '  effective password policy for EVERY domain account:' -ForegroundColor Yellow
        Write-Host ''
        Write-Host "    MinPasswordLength    : $($current.MinPasswordLength) -> $MinPasswordLength" -ForegroundColor Yellow
        Write-Host "    LockoutThreshold     : $($current.LockoutThreshold) -> $LockoutThreshold" -ForegroundColor Yellow
        Write-Host "    LockoutDuration      : $($current.LockoutDuration.TotalMinutes) min -> $LockoutDurationMinutes min" -ForegroundColor Yellow
        Write-Host "    LockoutObservation   : $($current.LockoutObservationWindow.TotalMinutes) min -> $LockoutObservationMinutes min" -ForegroundColor Yellow
        Write-Host "    MaxPasswordAge       : $($current.MaxPasswordAge.TotalDays) days -> $maxAgeDisplay" -ForegroundColor Yellow
        Write-Host "    ComplexityEnabled    : $($current.ComplexityEnabled) -> True" -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  Effective after the next Group Policy refresh on the PDC' -ForegroundColor Yellow
        Write-Host '  emulator. Existing passwords are not retroactively invalidated;' -ForegroundColor Yellow
        Write-Host '  new and changed passwords must meet the baseline.' -ForegroundColor Yellow
        Write-Host '  =============================================================' -ForegroundColor Yellow
        Write-Host ''

        # Skip the typed-confirmation gate under -WhatIf: a dry run mutates
        # nothing, so the destructive-action gate has nothing to guard, and
        # prompting here would break the preview (and throw in NonInteractive
        # mode). ShouldProcess below still emits the "What if:" line.
        if (-not $IAcknowledgeThisAffectsAllUsers -and -not $WhatIfPreference) {
            Write-Host 'Type the exact phrase YES I UNDERSTAND to proceed, anything else to abort:' -ForegroundColor Yellow
            $typed = Read-Host
            if ($typed -cne 'YES I UNDERSTAND') {
                Write-ADHLog -Level WARN -Message 'ADH-009 fix aborted: typed-confirmation gate not satisfied.' -Console
                $changeRecord.ErrorMessage = 'Aborted: typed-confirmation gate not satisfied.'
                return $changeRecord
            }
        } elseif ($IAcknowledgeThisAffectsAllUsers) {
            Write-ADHLog -Level FIX -Message 'ADH-009 fix: typed-confirmation bypassed via -IAcknowledgeThisAffectsAllUsers.' -Console
        }

        if (-not $PSCmdlet.ShouldProcess(
            "Domain GPO '$GpoName' (linked + enforced at root)",
            "Apply account-policy baseline (min length $MinPasswordLength, lockout $LockoutThreshold/$LockoutDurationMinutes min, complexity on, max age $maxAgeDisplay)")) {
            return $changeRecord
        }

        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if (-not $existingGpo) {
            Write-ADHLog -Level FIX -Message "Creating GPO: $GpoName" -Console
            $gpo = New-GPO -Name $GpoName -Comment 'Created by Invoke-ADHardening - AD hardening settings'
        } else {
            $gpo = $existingGpo
        }

        Write-ADHLog -Level FIX -Message 'Writing [System Access] account-policy baseline into GPO' -Console
        Set-ADHGpoSystemAccess -GpoId $gpo.Id -Setting @{
            MinimumPasswordLength = $MinPasswordLength
            PasswordComplexity    = 1
            LockoutBadCount       = $LockoutThreshold
            LockoutDuration       = $LockoutDurationMinutes
            ResetLockoutCount     = $LockoutObservationMinutes
            MaximumPasswordAge    = $maxAgeInf
        } | Out-Null

        # Link + ENFORCE at the domain root. Required: domain account policy only
        # applies from a domain-root-linked GPO, and Enforced makes it win over
        # the Default Domain Policy regardless of link order.
        $domainDn = (Get-ADDomain -ErrorAction Stop).DistinguishedName
        $existingLink = Get-GPInheritance -Target $domainDn |
            Select-Object -ExpandProperty GpoLinks |
            Where-Object { $_.GpoId -eq $gpo.Id }
        if (-not $existingLink) {
            Write-ADHLog -Level FIX -Message "Linking GPO at domain root (Enabled + Enforced): $domainDn" -Console
            New-GPLink -Guid $gpo.Id -Target $domainDn -LinkEnabled Yes -Enforced Yes | Out-Null
        } else {
            Write-ADHLog -Level FIX -Message 'Ensuring domain-root link is Enabled + Enforced' -Console
            Set-GPLink -Guid $gpo.Id -Target $domainDn -LinkEnabled Yes -Enforced Yes | Out-Null
        }

        $changeRecord.AfterState = @{
            Source       = 'Invoke-ADHardening Hardening GPO ([System Access])'
            GpoName      = $GpoName
            GpoId        = $gpo.Id
            LinkedAtRoot = $true
            Enforced     = $true
            MinimumPasswordLength = $MinPasswordLength
            PasswordComplexity    = 1
            LockoutBadCount       = $LockoutThreshold
            LockoutDuration       = $LockoutDurationMinutes
            ResetLockoutCount     = $LockoutObservationMinutes
            MaximumPasswordAge    = $maxAgeInf
        }
        $changeRecord.Success = $true

        Write-ADHLog -Level FIX -Message 'ADH-009 Password Policy - GPO baseline applied (effective after GP refresh on the PDC emulator)' -Console
    }
    catch {
        $changeRecord.ErrorMessage = $_.Exception.Message
        Write-ADHLog -Level ERROR -Message "ADH-009 fix failed: $($_.Exception.Message)" -Console
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
