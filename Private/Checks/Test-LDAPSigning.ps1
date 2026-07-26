function Test-LDAPSigning {
    <#
    .SYNOPSIS
        ADH-004 - Verifies LDAP Signing and Channel Binding are enforced by
        Group Policy on the Domain Controllers OU.
    .DESCRIPTION
        Inspects the Group Policy Objects that apply to the Domain Controllers
        OU (including inherited links from the domain root) for the two NTDS
        parameters that enforce LDAP integrity:

          LDAPServerIntegrity       = 2  ("Require signing")
          LdapEnforceChannelBinding = 2  ("Always")

        Both map to the registry key
          HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
        but Microsoft ships them as *Security Options*
        ("Domain controller: LDAP server signing requirements" /
        "...channel binding token requirements"), so they live in GptTmpl.inf,
        not registry.pol. Get-ADHGpoSettingForOu handles both representations
        (registry policy first, then Security-Options XML fallback).

        This is a *policy-intent* check: it proves what GPO will push to the
        DCs after gpupdate, not what each DC's live registry currently holds.
        That deliberately replaces the previous WinRM/remote-registry approach,
        which required local-admin-over-WinRM on every DC and produced
        confusing "unreachable" results when run as Domain Admin on the DC
        console (a single missing registry value made Get-ItemProperty throw
        and looked like a connectivity failure).

        Effective value semantics: when more than one GPO defines a value, the
        highest-precedence link wins. Get-ADHGpoSettingForOu returns rows in
        GPO precedence order, so the first row for each value name is effective.

        Status semantics:
          Pass  : the effective GPO value for BOTH settings is 2.
          Fail  : either setting is undefined by any applicable GPO (so the DC
                  default of non-enforcement stands) or defined with a value
                  other than 2.
          Error : GPO/AD discovery itself failed.

        Severity is Critical because lack of signing + channel binding enables
        NTLM relay all the way to LDAP/LDAPS authentication, the primary path
        used by tools like ntlmrelayx -t ldap[s]://dc --escalate-user.
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-004 LDAP Signing + Channel Binding - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-004'
        CheckName  = 'LDAP Signing + Channel Binding Enforced'
        Category   = 'Relay Defenses'
        Severity   = 'Critical'
        References = @(
            'https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-active-directory-domain-controller-ad-dc-f0fcae21-e1ae-4ddb-49ca-2bbf91d4cabb',
            'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/ldap-signing-rqmts',
            'https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py',
            'MITRE ATT&CK T1557.001'
        )
    }

    $regKey = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $dcOu   = "OU=Domain Controllers,$($domain.DistinguishedName)"

        # Effective value = first (highest-precedence) GPO definition.
        $signingDefs = @(Get-ADHGpoSettingForOu -OuDN $dcOu -RegistryKey $regKey `
                -ValueName 'LDAPServerIntegrity' -IncludeInherited)
        $cbDefs      = @(Get-ADHGpoSettingForOu -OuDN $dcOu -RegistryKey $regKey `
                -ValueName 'LdapEnforceChannelBinding' -IncludeInherited)

        $signingEffective = if ($signingDefs.Count -gt 0) { [int]$signingDefs[0].Value } else { $null }
        $cbEffective      = if ($cbDefs.Count -gt 0)      { [int]$cbDefs[0].Value }      else { $null }

        $signingOk = ($signingEffective -eq 2)
        $cbOk      = ($cbEffective -eq 2)

        # Build a human-readable per-setting state list and the set of GPOs
        # that contribute (for AffectedObjects when something is wrong).
        $problems = @()
        if (-not $signingOk) {
            $problems += if ($null -eq $signingEffective) {
                'LDAPServerIntegrity is not configured by any applicable GPO (DCs default to "negotiate", not "require")'
            } else {
                "LDAPServerIntegrity effective value is $signingEffective (need 2)"
            }
        }
        if (-not $cbOk) {
            $problems += if ($null -eq $cbEffective) {
                'LdapEnforceChannelBinding is not configured by any applicable GPO (DCs default to non-enforcement)'
            } else {
                "LdapEnforceChannelBinding effective value is $cbEffective (need 2)"
            }
        }

        $contributingGpos = @($signingDefs + $cbDefs | ForEach-Object { $_.GpoName } |
                Where-Object { $_ } | Sort-Object -Unique)

        $evidence = @{
            AuditMethod        = 'GPO inspection of the Domain Controllers OU (Get-ADHGpoSettingForOu: registry-policy probe, then Security-Options XML fallback). Inherited links from the domain root are included.'
            RequiresElevation  = $false
            ElevationContext   = 'Reads GPO definitions via RSAT GroupPolicy cmdlets; needs GPO read rights (any authenticated user by default), not local admin on each DC.'
            Limitations        = 'Reflects policy intent (what GPO will push), not each DC live registry state. A DC that has not yet applied policy, or has a local/manual override, can differ until gpupdate. The on-the-wire LDAP bind probe (Invoke-ADHLdapSigningProbe, akin to LdapRelayScan / NetExec ldap) measures actual behaviour without DC admin; an opt-in on-the-wire probe is on the project roadmap.'
            DCOuDN             = $dcOu
            LDAPServerIntegrity        = @{ Effective = $signingEffective; Definitions = $signingDefs }
            LdapEnforceChannelBinding  = @{ Effective = $cbEffective;      Definitions = $cbDefs }
            ContributingGpos   = $contributingGpos
            Problems           = $problems
        }

        if ($signingOk -and $cbOk) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description "GPO on the Domain Controllers OU enforces LDAPServerIntegrity=2 and LdapEnforceChannelBinding=2." `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-004 LDAP Signing + Channel Binding - PASS' -Console
        }
        else {
            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "LDAP signing + channel binding is not enforced by Group Policy on the Domain Controllers OU: $($problems -join '; '). Unsigned LDAP and unprotected LDAPS sessions allow NTLM relay attacks to escalate to domain admin via tools like ntlmrelayx." `
                -Evidence $evidence `
                -AffectedObjects $dcOu `
                -RemediationSteps 'Configure, on a GPO linked to the Domain Controllers OU: "Domain controller: LDAP server signing requirements" = Require signing (LDAPServerIntegrity=2) and "Domain controller: LDAP server channel binding token requirements" = Always (LdapEnforceChannelBinding=2). WARNING: legacy LDAP clients (some printers, older Linux LDAP code, line-of-business apps) may break. Test first. Run: Invoke-ADHardening -Mode Implement -IncludeCheckIds ADH-004' `
                -AutoFixAvailable $true `
                -FixFunction 'Set-LDAPSigningEnforced'

            Write-ADHLog -Level FAIL -Message "ADH-004 LDAP Signing + Channel Binding - FAIL ($($problems -join '; '))" -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-004 LDAP Signing + Channel Binding - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
