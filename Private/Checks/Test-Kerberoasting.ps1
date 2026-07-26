function Test-Kerberoasting {
    <#
    .SYNOPSIS
        ADH-007 - Enumerates Kerberoastable and AS-REP-roastable accounts.
    .DESCRIPTION
        Read-only enumeration. We never request service tickets - that's
        the attack. We only identify exposure surface:

          Kerberoastable: any enabled user with a non-null SPN. An attacker
            with any domain user creds can request a service ticket and
            offline-crack it.

          AS-REP roastable: any user with DoesNotRequirePreAuth=$true. An
            attacker without any creds can request a TGT and offline-crack
            the response.

        Severity escalation for kerberoastable accounts (per the build spec):
          Critical when the account is in Domain/Enterprise/Schema Admins
          or has AdminCount=1, OR password is older than 365 days.
          High otherwise.

        AS-REP roastable accounts are always at least High; same escalation
        rules apply for the overall finding severity.

        Finding has a single Severity field, so we take the worst over all
        affected accounts. Per-account severity is in Evidence.Accounts.
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-007 Kerberoasting + AS-REP Roasting - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-007'
        CheckName  = 'Kerberoasting / AS-REP Roasting exposure'
        Category   = 'Credential Attacks'
        Severity   = 'High'  # overridden below if any Critical account exists
        References = @(
            'https://attack.mitre.org/techniques/T1558/003/',
            'https://attack.mitre.org/techniques/T1558/004/',
            'https://www.specterops.io/assets/resources/Cracking_Kerberos_TGS_Tickets_Using_Kerberoast.pdf',
            'https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/'
        )
    }

    $evidence = @{
        AuditMethod       = 'AD attribute read (no Kerberos ticket requests issued)'
        RequiresElevation = $false
        Limitations       = 'Detects exposure surface only. Whether each account is actually crackable depends on its password complexity, which we cannot test from inside AD.'
        Accounts          = @()
    }

    $privilegedGroupSids = @(
        'S-1-5-21-*-512'   # Domain Admins
        'S-1-5-21-*-518'   # Schema Admins
        'S-1-5-21-*-519'   # Enterprise Admins
    )

    function _isPrivileged($user, $domainSid) {
        if ($user.AdminCount -eq 1) { return $true }
        $da = "$domainSid-512"
        $sa = "$domainSid-518"
        $ea = "$domainSid-519"
        foreach ($g in @($user.MemberOf)) {
            if ($g -match 'CN=Domain Admins,'     -or
                $g -match 'CN=Enterprise Admins,' -or
                $g -match 'CN=Schema Admins,') { return $true }
        }
        return $false
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $domainSid = $domain.DomainSID.Value

        # Kerberoastable: enabled users with SPNs (exclude krbtgt and machine accounts)
        $kerb = Get-ADUser `
            -Filter { ServicePrincipalName -like "*" -and Enabled -eq $true } `
            -Properties ServicePrincipalName, PasswordLastSet, MemberOf, AdminCount -ErrorAction Stop |
            Where-Object { $_.SamAccountName -ne 'krbtgt' }

        $asrep = Get-ADUser `
            -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } `
            -Properties DoesNotRequirePreAuth, PasswordLastSet, MemberOf, AdminCount -ErrorAction Stop

        $accounts = New-Object System.Collections.Generic.List[object]
        $worstSeverity = 'Info'

        foreach ($u in $kerb) {
            $privileged = _isPrivileged $u $domainSid
            $pwdAgeDays = if ($u.PasswordLastSet) {
                [int]((Get-Date) - $u.PasswordLastSet).TotalDays
            } else { -1 }
            $oldPwd = ($pwdAgeDays -gt 365)

            $sev = if ($privileged -or $oldPwd) { 'Critical' } else { 'High' }
            if ($sev -eq 'Critical') { $worstSeverity = 'Critical' }
            elseif ($worstSeverity -ne 'Critical') { $worstSeverity = 'High' }

            $accounts.Add([PSCustomObject]@{
                SamAccountName  = $u.SamAccountName
                Exposure        = 'Kerberoastable'
                SPNs            = ($u.ServicePrincipalName -join ', ')
                PrivilegedGroup = $privileged
                PasswordAgeDays = $pwdAgeDays
                Severity        = $sev
            })
        }

        foreach ($u in $asrep) {
            $privileged = _isPrivileged $u $domainSid
            $pwdAgeDays = if ($u.PasswordLastSet) {
                [int]((Get-Date) - $u.PasswordLastSet).TotalDays
            } else { -1 }
            $oldPwd = ($pwdAgeDays -gt 365)

            $sev = if ($privileged -or $oldPwd) { 'Critical' } else { 'High' }
            if ($sev -eq 'Critical') { $worstSeverity = 'Critical' }
            elseif ($worstSeverity -ne 'Critical') { $worstSeverity = 'High' }

            $accounts.Add([PSCustomObject]@{
                SamAccountName  = $u.SamAccountName
                Exposure        = 'AS-REP roastable'
                SPNs            = ''
                PrivilegedGroup = $privileged
                PasswordAgeDays = $pwdAgeDays
                Severity        = $sev
            })
        }

        # NB: use .ToArray() rather than @($accounts). Wrapping a
        # System.Collections.Generic.List[object] in the @() array-subexpression
        # operator throws "Argument types do not match" on PowerShell 7.6.x
        # (and on the lab DC). .ToArray() is the safe materialisation.
        $evidence.Accounts = $accounts.ToArray()
        $checkParams.Severity = $worstSeverity

        if ($accounts.Count -eq 0) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description 'No Kerberoastable user accounts and no AS-REP roastable accounts found.' `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-007 Kerberoasting - PASS' -Console
        }
        else {
            $critCount = @($accounts | Where-Object Severity -eq 'Critical').Count
            $kerbCount = @($accounts | Where-Object Exposure -eq 'Kerberoastable').Count
            $asrepCount = @($accounts | Where-Object Exposure -eq 'AS-REP roastable').Count

            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "$kerbCount Kerberoastable account(s), $asrepCount AS-REP roastable account(s); $critCount of these are privileged or have aged credentials (>365d)." `
                -Evidence $evidence `
                -AffectedObjects @($accounts | ForEach-Object SamAccountName) `
                -RemediationSteps @"
No safe auto-fix - service-account password changes have cascading effects.

For each Kerberoastable account:
  1. Rotate the password to >= 25 chars random (effectively un-crackable offline).
  2. Migrate to a Group Managed Service Account (gMSA) if the consuming service supports it.
  3. Add highly privileged accounts to the Protected Users group AND mark the account "sensitive and cannot be delegated".

For each AS-REP roastable account:
  1. Remove DoesNotRequirePreAuth on the account (uncheck "Do not require Kerberos preauthentication" in ADUC) - then rotate the password.

Track this list with Invoke-ADHardening reports over time; aim to reduce the count quarter over quarter.
"@ `
                -AutoFixAvailable $false

            Write-ADHLog -Level FAIL -Message "ADH-007 Kerberoasting - FAIL (kerb=$kerbCount, asrep=$asrepCount, critical=$critCount)" -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-007 Kerberoasting - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
