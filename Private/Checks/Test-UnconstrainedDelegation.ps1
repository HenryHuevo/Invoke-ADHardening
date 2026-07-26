function Test-UnconstrainedDelegation {
    <#
    .SYNOPSIS
        ADH-008 - Enumerates unconstrained delegation on non-DC accounts.
    .DESCRIPTION
        Any non-DC computer with TrustedForDelegation=$true caches TGTs for
        every user that authenticates to it - so compromising that host
        yields TGTs for those users, including potentially Domain Admins
        (e.g. via the printer-bug + relay chain). Same goes for any user
        account with TrustedForDelegation.

        DCs are filtered out by PrimaryGroupID -ne 516 (516 = Domain
        Controllers). RODCs have a different flag and are still in scope
        if found.

        Severity: Critical when any non-DC computer or any user has
        unconstrained delegation. No auto-fix - removing delegation can
        break legitimate Kerberos-dependent services.
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-008 Unconstrained Delegation - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-008'
        CheckName  = 'Unconstrained Delegation on non-DCs'
        Category   = 'Delegation'
        Severity   = 'Critical'
        References = @(
            'https://attack.mitre.org/techniques/T1558/003/',
            'https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1',
            'https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/',
            'MITRE ATT&CK T1134.001'
        )
    }

    $evidence = @{
        AuditMethod       = 'AD attribute read (userAccountControl / TrustedForDelegation)'
        RequiresElevation = $false
        Limitations       = 'Detects classic unconstrained delegation only. Resource-Based Constrained Delegation abuses (RBCD via msDS-AllowedToActOnBehalfOfOtherIdentity) are a separate class and should be audited with BloodHound / Get-ADComputer queries on that attribute.'
        Computers         = @()
        Users             = @()
    }

    try {
        $computers = Get-ADComputer `
            -Filter { TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516 } `
            -Properties TrustedForDelegation, PrimaryGroupID, OperatingSystem, LastLogonDate, Enabled -ErrorAction Stop

        $users = Get-ADUser `
            -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, Enabled, LastLogonDate, AdminCount, MemberOf -ErrorAction Stop

        $evidence.Computers = @($computers | ForEach-Object {
            [PSCustomObject]@{
                Name             = $_.Name
                DNSHostName      = $_.DNSHostName
                OS               = $_.OperatingSystem
                Enabled          = $_.Enabled
                LastLogonDate    = $_.LastLogonDate
                DistinguishedName = $_.DistinguishedName
            }
        })

        $evidence.Users = @($users | ForEach-Object {
            $privileged = ($_.AdminCount -eq 1)
            [PSCustomObject]@{
                SamAccountName    = $_.SamAccountName
                Enabled           = $_.Enabled
                Privileged        = $privileged
                LastLogonDate     = $_.LastLogonDate
                DistinguishedName = $_.DistinguishedName
            }
        })

        $totalAffected = $evidence.Computers.Count + $evidence.Users.Count

        if ($totalAffected -eq 0) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description 'No non-DC computer or user accounts have unconstrained delegation enabled.' `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-008 Unconstrained Delegation - PASS' -Console
        }
        else {
            $affected = @()
            $affected += $evidence.Computers | ForEach-Object DNSHostName
            $affected += $evidence.Users | ForEach-Object SamAccountName
            $affected = @($affected | Where-Object { $_ })

            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "$($evidence.Computers.Count) non-DC computer(s) and $($evidence.Users.Count) user(s) have unconstrained delegation. Compromise of any of these yields cached TGTs for every authenticating user, including potential paths to domain admin." `
                -Evidence $evidence `
                -AffectedObjects $affected `
                -RemediationSteps @"
No safe auto-fix - delegation removal can break legitimate Kerberos services.

For each affected non-DC computer:
  1. Verify which service requires delegation. Most legitimately need constrained delegation, not unconstrained.
  2. Migrate to constrained delegation (Kerberos-only) with msDS-AllowedToDelegateTo limited to specific SPNs, or
  3. Migrate to resource-based constrained delegation (RBCD), defined on the target rather than the source, or
  4. If delegation is unnecessary, uncheck "Trust this computer for delegation to any service" in ADUC.

For each affected user:
  - Almost never legitimate. Remove "Trust this account for delegation" in ADUC.
  - Add highly privileged accounts to the Protected Users group AND mark "sensitive and cannot be delegated".
"@ `
                -AutoFixAvailable $false

            Write-ADHLog -Level FAIL -Message "ADH-008 Unconstrained Delegation - FAIL (computers=$($evidence.Computers.Count), users=$($evidence.Users.Count))" -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-008 Unconstrained Delegation - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
