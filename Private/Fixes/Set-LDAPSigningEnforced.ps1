function Set-LDAPSigningEnforced {
    <#
    .SYNOPSIS
        ADH-004 fix - enforces LDAPServerIntegrity=2 and
        LdapEnforceChannelBinding=2 via a GPO linked to the Domain Controllers OU.
    .DESCRIPTION
        Creates (or updates) a separate GPO named 'Invoke-ADHardening DC Hardening'
        and links it to the Domain Controllers OU. The general-purpose
        'Invoke-ADHardening Hardening' GPO is NOT used here - DC settings
        belong on a dedicated, narrowly-scoped GPO so they cannot accidentally
        apply to member servers.

        The link is created (and, if pre-existing, upgraded to) ENFORCED. An
        enforced link wins regardless of link order, so our LDAPServerIntegrity=2
        beats any higher-precedence GPO on the OU - notably the Default Domain
        Controllers Policy, which commonly sets LDAPServerIntegrity=1 as a
        Security Option and would otherwise override us (it sits at link order 1
        while a freshly added link lands at the bottom / lowest precedence).
        Enforcement also defeats block-inheritance on the OU.

        Configures both as the named Security Options (stored in GptTmpl.inf,
        NOT registry.pol):
          - "Domain controller: LDAP server signing requirements"        = Require signing  (LDAPServerIntegrity=2)
          - "Domain controller: LDAP server channel binding token requirements" = Always   (LdapEnforceChannelBinding=2)
        which both land under
          MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
        We write them via Set-ADHGpoSecurityOption so GPMC shows them as the
        named Security Options rather than "Extra Registry Settings".

        CONFIRMATION GATE:
        This fix can break legacy LDAP clients (some printers, older Linux
        LDAP code, line-of-business apps that do not bind with sign/seal or
        do not provide channel binding tokens). The function refuses to run
        unless EITHER:
          - the -IAcknowledgeThisCanBreakLegacyApps switch is present, OR
          - the operator interactively types: YES I UNDERSTAND
        ...AND ShouldProcess approval is given (-Confirm:$false bypasses the
        ShouldProcess prompt only; the typed-confirmation gate above is
        independent and not skippable except via the switch).
    .PARAMETER GpoName
        GPO name. Defaults to 'Invoke-ADHardening DC Hardening'.
    .PARAMETER IAcknowledgeThisCanBreakLegacyApps
        Skips the interactive typed-confirmation prompt. Required for
        unattended runs.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$GpoName = 'Invoke-ADHardening DC Hardening',
        [switch]$IAcknowledgeThisCanBreakLegacyApps
    )

    $changeRecord = [PSCustomObject]@{
        CheckId      = 'ADH-004'
        FixFunction  = 'Set-LDAPSigningEnforced'
        Timestamp    = [DateTime]::UtcNow
        BeforeState  = $null
        AfterState   = $null
        Success      = $false
        ErrorMessage = $null
    }

    # Security-Option key paths (MACHINE\..., as they appear in GptTmpl.inf).
    $signingSecOpt = 'MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
    $cbSecOpt      = 'MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'

    try {
        Write-Host ''
        Write-Host '  =============================================================' -ForegroundColor Yellow
        Write-Host '  WARNING - ADH-004 LDAP Signing + Channel Binding Enforcement' -ForegroundColor Yellow
        Write-Host '  =============================================================' -ForegroundColor Yellow
        Write-Host '  Enforcing LDAPServerIntegrity=2 and LdapEnforceChannelBinding=2' -ForegroundColor Yellow
        Write-Host '  on every Domain Controller can break:' -ForegroundColor Yellow
        Write-Host '    - Legacy printers / MFPs binding to LDAP' -ForegroundColor Yellow
        Write-Host '    - Older Linux/Unix LDAP clients without sign/seal' -ForegroundColor Yellow
        Write-Host '    - Line-of-business apps without channel binding support' -ForegroundColor Yellow
        Write-Host '    - Some appliances (NAS, scanners) authenticating via LDAP' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  Validate every LDAP-binding client BEFORE applying. Watch' -ForegroundColor Yellow
        Write-Host '  Directory Services event log IDs 2887 / 2889 for clients' -ForegroundColor Yellow
        Write-Host '  that would break.' -ForegroundColor Yellow
        Write-Host '  =============================================================' -ForegroundColor Yellow
        Write-Host ''

        # Skip the typed-confirmation gate under -WhatIf: a dry run mutates
        # nothing, so the destructive-action gate has nothing to guard, and
        # prompting here would break the preview (and throw in NonInteractive
        # mode). ShouldProcess below still emits the "What if:" line.
        if (-not $IAcknowledgeThisCanBreakLegacyApps -and -not $WhatIfPreference) {
            Write-Host 'Type the exact phrase YES I UNDERSTAND to proceed, anything else to abort:' -ForegroundColor Yellow
            $typed = Read-Host
            if ($typed -cne 'YES I UNDERSTAND') {
                Write-ADHLog -Level WARN -Message 'ADH-004 fix aborted: typed-confirmation gate not satisfied.' -Console
                $changeRecord.ErrorMessage = 'Aborted: typed-confirmation gate not satisfied.'
                return $changeRecord
            }
        } elseif ($IAcknowledgeThisCanBreakLegacyApps) {
            Write-ADHLog -Level FIX -Message 'ADH-004 fix: typed-confirmation bypassed via -IAcknowledgeThisCanBreakLegacyApps.' -Console
        }

        $domain   = Get-ADDomain -ErrorAction Stop
        $dcOuDn   = "OU=Domain Controllers,$($domain.DistinguishedName)"

        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        $before = @{ GpoExists = [bool]$existingGpo; DomainControllersOU = $dcOuDn }
        if ($existingGpo) {
            $before.GpoId                       = $existingGpo.Id
            $before.LDAPServerIntegrity         = Get-ADHGpoSecurityOption -GpoId $existingGpo.Id -KeyName $signingSecOpt
            $before.LdapEnforceChannelBinding   = Get-ADHGpoSecurityOption -GpoId $existingGpo.Id -KeyName $cbSecOpt
            $existingLinkBefore = Get-GPInheritance -Target $dcOuDn -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty GpoLinks |
                Where-Object { $_.GpoId -eq $existingGpo.Id }
            $before.Linked      = [bool]$existingLinkBefore
            $before.LinkEnforced = [bool]$existingLinkBefore.Enforced
        }
        $changeRecord.BeforeState = $before

        if (-not $PSCmdlet.ShouldProcess(
            "DC OU '$dcOuDn' via GPO '$GpoName'",
            "Set LDAPServerIntegrity=2 and LdapEnforceChannelBinding=2 (enforce LDAP signing + channel binding)")) {
            return $changeRecord
        }

        if (-not $existingGpo) {
            Write-ADHLog -Level FIX -Message "Creating GPO: $GpoName" -Console
            $gpo = New-GPO -Name $GpoName -Comment 'Created by Invoke-ADHardening - DC hardening (LDAP signing + channel binding)'
        } else {
            $gpo = $existingGpo
        }

        Write-ADHLog -Level FIX -Message 'Setting Security Options: LDAP server signing = Require signing, channel binding = Always' -Console
        Set-ADHGpoSecurityOption -GpoId $gpo.Id -Setting @(
            @{ KeyName = $signingSecOpt; Type = 4; Value = 2 },
            @{ KeyName = $cbSecOpt;      Type = 4; Value = 2 }
        ) | Out-Null

        $existingLink = Get-GPInheritance -Target $dcOuDn |
            Select-Object -ExpandProperty GpoLinks |
            Where-Object { $_.GpoId -eq $gpo.Id }

        if (-not $existingLink) {
            Write-ADHLog -Level FIX -Message "Linking GPO to Domain Controllers OU (enforced): $dcOuDn" -Console
            New-GPLink -Guid $gpo.Id -Target $dcOuDn -LinkEnabled Yes -Enforced Yes | Out-Null
        } elseif (-not $existingLink.Enforced) {
            Write-ADHLog -Level FIX -Message "Enforcing existing GPO link on Domain Controllers OU so it wins over higher-precedence GPOs: $dcOuDn" -Console
            Set-GPLink -Guid $gpo.Id -Target $dcOuDn -Enforced Yes | Out-Null
        } else {
            Write-ADHLog -Level FIX -Message "GPO link already enforced on Domain Controllers OU: $dcOuDn" -Console
        }

        $changeRecord.AfterState = @{
            GpoExists                  = $true
            GpoId                      = $gpo.Id
            LDAPServerIntegrity        = 2
            LdapEnforceChannelBinding  = 2
            LinkedTo                   = $dcOuDn
            LinkEnforced               = $true
        }
        $changeRecord.Success = $true

        Write-ADHLog -Level FIX -Message 'ADH-004 LDAP Signing + Channel Binding - FIX applied. Settings take effect after the next DC GPO refresh (or gpupdate /force on each DC). Existing LDAP sessions are not retroactively rejected.' -Console
    }
    catch {
        $changeRecord.ErrorMessage = $_.Exception.Message
        Write-ADHLog -Level ERROR -Message "ADH-004 fix failed: $($_.Exception.Message)" -Console
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
