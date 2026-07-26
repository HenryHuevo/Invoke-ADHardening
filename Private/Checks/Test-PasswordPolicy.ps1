function Test-PasswordPolicy {
    <#
    .SYNOPSIS
        ADH-009 - Verifies the Default Domain Password Policy meets baseline.
    .DESCRIPTION
        Cumulative check - any failing condition fails the overall finding.
        Each condition is reported individually in Evidence.FailedConditions
        so an operator can see exactly which knobs are wrong.

        Baseline (overrideable in future via parameters; locked for v1):
          MinPasswordLength   >= 14
          LockoutThreshold     between 1 and 10 inclusive
          LockoutDuration      >= 15 minutes
          MaxPasswordAge       <= 365 days; 0 (never expire) is allowed
                               (NIST SP 800-63B: don't force periodic rotation)
          ComplexityEnabled    = $true

        Also enumerates enabled accounts with PasswordNeverExpires = $true
        and reports the count.
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-009 Password Policy - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-009'
        CheckName  = 'Password Policy Baseline'
        Category   = 'Account Hardening'
        Severity   = 'High'
        References = @(
            'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy',
            'https://pages.nist.gov/800-63-3/sp800-63b.html',
            'MITRE ATT&CK T1110'
        )
    }

    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop

        $failedConditions = @()

        if ($policy.MinPasswordLength -lt 14) {
            $failedConditions += [PSCustomObject]@{
                Setting  = 'MinPasswordLength'
                Current  = $policy.MinPasswordLength
                Expected = '>= 14'
            }
        }

        $lockoutThreshold = [int]$policy.LockoutThreshold
        if ($lockoutThreshold -eq 0 -or $lockoutThreshold -gt 10) {
            $failedConditions += [PSCustomObject]@{
                Setting  = 'LockoutThreshold'
                Current  = $lockoutThreshold
                Expected = '1..10 (0 disables lockout)'
            }
        }

        if ($policy.LockoutDuration.TotalMinutes -lt 15) {
            $failedConditions += [PSCustomObject]@{
                Setting  = 'LockoutDuration'
                Current  = "$($policy.LockoutDuration.TotalMinutes) min"
                Expected = '>= 15 min'
            }
        }

        $maxPwdDays = $policy.MaxPasswordAge.TotalDays
        if ($maxPwdDays -gt 365) {
            $failedConditions += [PSCustomObject]@{
                Setting  = 'MaxPasswordAge'
                Current  = "$maxPwdDays days"
                Expected = '<= 365 days, or 0 (never expire - allowed, NIST 800-63B)'
            }
        }

        if (-not $policy.ComplexityEnabled) {
            $failedConditions += [PSCustomObject]@{
                Setting  = 'ComplexityEnabled'
                Current  = $false
                Expected = $true
            }
        }

        # PasswordNeverExpires enumeration (informational; doesn't fail the check on its own)
        $pwdNeverExpiresCount = 0
        $pwdNeverExpiresSample = @()
        try {
            $pwdNeverExpiresUsers = Get-ADUser `
                -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
                -Properties PasswordNeverExpires, AdminCount -ErrorAction Stop
            $pwdNeverExpiresCount  = @($pwdNeverExpiresUsers).Count
            $pwdNeverExpiresSample = @($pwdNeverExpiresUsers | Select-Object -First 10 |
                ForEach-Object { $_.SamAccountName })
        } catch {
            Write-ADHLog -Level WARN -Message "Could not enumerate PasswordNeverExpires users: $($_.Exception.Message)" -Console
        }

        $evidence = @{
            AuditMethod       = 'AD attribute read (Get-ADDefaultDomainPasswordPolicy + Get-ADUser filter)'
            RequiresElevation = $false
            Limitations       = 'Reads the Default Domain Password Policy only. Fine-Grained Password Policies (FGPP) targeting groups/users are not enumerated here - run Get-ADFineGrainedPasswordPolicy separately if they are in use.'
            CurrentPolicy = [PSCustomObject]@{
                MinPasswordLength       = $policy.MinPasswordLength
                LockoutThreshold        = $lockoutThreshold
                LockoutDurationMinutes  = $policy.LockoutDuration.TotalMinutes
                MaxPasswordAgeDays      = $maxPwdDays
                MinPasswordAgeDays      = $policy.MinPasswordAge.TotalDays
                PasswordHistoryCount    = $policy.PasswordHistoryCount
                ComplexityEnabled       = $policy.ComplexityEnabled
            }
            FailedConditions      = $failedConditions
            PasswordNeverExpires  = @{
                EnabledAccountCount = $pwdNeverExpiresCount
                Sample              = $pwdNeverExpiresSample
            }
        }

        if ($failedConditions.Count -eq 0) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description "Default domain password policy meets baseline (length>=14, lockout 1-10, lockout duration>=15min, max age<=365d or never-expire, complexity on). $pwdNeverExpiresCount enabled accounts have PasswordNeverExpires set - review separately." `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-009 Password Policy - PASS' -Console
        }
        else {
            $summary = ($failedConditions | ForEach-Object { "$($_.Setting)=$($_.Current)" }) -join ', '
            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "Default domain password policy fails $($failedConditions.Count) baseline check(s): $summary" `
                -Evidence $evidence `
                -RemediationSteps 'Adjust Default Domain Password Policy to meet baseline. Run: Invoke-ADHardening -Mode Implement -IncludeCheckIds ADH-009. WARNING: tightening MaxPasswordAge or complexity can trigger widespread forced resets.' `
                -AutoFixAvailable $true `
                -FixFunction 'Set-PasswordPolicyBaseline'

            Write-ADHLog -Level FAIL -Message "ADH-009 Password Policy - FAIL ($($failedConditions.Count) conditions)" -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-009 Password Policy - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
