function Set-IPv6Mitm6Mitigated {
    <#
    .SYNOPSIS
        ADH-005 fix - adds Windows Firewall rules to the Invoke-ADHardening
        Hardening GPO that BLOCK the IPv6 flows mitm6 abuses (rogue DHCPv6 and
        rogue Router Advertisements).
    .DESCRIPTION
        Creates three Block rules in the named hardening GPO's firewall policy
        store - the host-level fallback to switch-level RA Guard / DHCPv6 Guard.
        Each mirrors a built-in "Core Networking" rule but with Action=Block:

          - Inbound  UDP 546           (DHCPv6 client - "DHCPV6-In")
          - Inbound  ICMPv6 Type 134   (Router Advertisement - "ICMPv6-In")
          - Outbound UDP 546 -> 547     (DHCPv6 client - "DHCPV6-Out")

        Firewall rules are NOT stored in registry.pol / GptTmpl.inf, so the
        Set-GPRegistryValue / Set-ADHGpoSecurityOption mechanisms used by the
        other fixes cannot express them. The only supported way to write a rule
        into a GPO is New-NetFirewallRule -PolicyStore "<domain>\<gpo>", which is
        exactly the write-mirror of how Test-IPv6Mitm6 reads them back via
        Get-NetFirewallRule -PolicyStore. The GPO is created if missing and
        optionally linked at the domain root.

        This does NOT replace switch-level RA Guard / DHCPv6 Guard, which is the
        preferred mitigation and lives on network gear we cannot configure from
        AD; it is defence-in-depth on the host. IPv6 itself is deliberately NOT
        disabled - the DisabledComponents registry value is unsupported by
        Microsoft on modern Windows and has caused production outages.

        NetSecurity ships in-box on Server 2012+/Windows 8+ (including every DC).
        If it is genuinely missing the fix throws rather than silently no-op.
    .PARAMETER GpoName
        GPO to create/update. Defaults to 'Invoke-ADHardening Hardening' - the
        same GPO used by the other broad-scope hardening fixes.
    .PARAMETER LinkAtDomainRoot
        Also link the GPO at the domain root (if not already linked).
    .NOTES
        Emits a change record (before/after state) to changes.jsonl.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$GpoName = 'Invoke-ADHardening Hardening',
        [switch]$LinkAtDomainRoot
    )

    $changeRecord = [PSCustomObject]@{
        CheckId      = 'ADH-005'
        FixFunction  = 'Set-IPv6Mitm6Mitigated'
        Timestamp    = [DateTime]::UtcNow
        BeforeState  = $null
        AfterState   = $null
        Success      = $false
        ErrorMessage = $null
    }

    # The three Block rules. The per-rule hashtable keys map straight onto
    # New-NetFirewallRule parameters (merged with the common splat below).
    $ruleSpecs = @(
        @{
            DisplayName = 'Invoke-ADHardening - Block DHCPv6 client (DHCPV6-In)'
            Description = 'Blocks inbound DHCPv6 (UDP 546). mitm6 / rogue-DHCPv6 mitigation (ADH-005).'
            Params      = @{ Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; LocalPort = '546' }
        },
        @{
            DisplayName = 'Invoke-ADHardening - Block IPv6 Router Advertisement (ICMPv6-In)'
            Description = 'Blocks inbound IPv6 Router Advertisements (ICMPv6 type 134). mitm6 mitigation (ADH-005).'
            Params      = @{ Direction = 'Inbound'; Action = 'Block'; Protocol = 'ICMPv6'; IcmpType = '134' }
        },
        @{
            DisplayName = 'Invoke-ADHardening - Block DHCPv6 client (DHCPV6-Out)'
            Description = 'Blocks outbound DHCPv6 (UDP 546 -> 547). mitm6 mitigation (ADH-005).'
            Params      = @{ Direction = 'Outbound'; Action = 'Block'; Protocol = 'UDP'; LocalPort = '546'; RemotePort = '547' }
        }
    )

    try {
        if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
            throw 'New-NetFirewallRule (NetSecurity module) is unavailable on this host. Run this fix from a DC or an RSAT management host.'
        }

        $dnsRoot     = (Get-ADDomain -ErrorAction Stop).DNSRoot
        $policyStore = "$dnsRoot\$GpoName"

        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        $before = @{
            GpoExists          = [bool]$existingGpo
            PolicyStore        = $policyStore
            ExistingBlockRules = @()
        }
        if ($existingGpo) {
            $before.GpoId = $existingGpo.Id
            foreach ($spec in $ruleSpecs) {
                $r = Get-NetFirewallRule -PolicyStore $policyStore -DisplayName $spec.DisplayName -ErrorAction SilentlyContinue
                if ($r) { $before.ExistingBlockRules += $spec.DisplayName }
            }
        }
        $changeRecord.BeforeState = $before

        if (-not $PSCmdlet.ShouldProcess(
            "Domain GPO '$GpoName'",
            'Create firewall rules blocking inbound DHCPv6 (UDP 546), inbound Router Advertisement (ICMPv6 134), and outbound DHCPv6 (UDP 546->547)')) {
            return $changeRecord
        }

        if (-not $existingGpo) {
            Write-ADHLog -Level FIX -Message "Creating GPO: $GpoName" -Console
            $gpo = New-GPO -Name $GpoName -Comment 'Created by Invoke-ADHardening - AD hardening settings'
        } else {
            $gpo = $existingGpo
        }

        $created = @()
        foreach ($spec in $ruleSpecs) {
            # Idempotency: drop any prior copy of this rule in the store so a
            # re-run does not accumulate duplicates. Absent rule -> nothing to do.
            try {
                Remove-NetFirewallRule -PolicyStore $policyStore -DisplayName $spec.DisplayName -ErrorAction Stop
                Write-ADHLog -Level FIX -Message "Removed existing rule before re-create: $($spec.DisplayName)" -Console
            } catch { }

            Write-ADHLog -Level FIX -Message "Creating Block rule: $($spec.DisplayName)" -Console
            $ruleParams = @{
                PolicyStore = $policyStore
                DisplayName = $spec.DisplayName
                Description = $spec.Description
                Group       = 'Invoke-ADHardening'
                Enabled     = 'True'
                Profile     = 'Any'
            }
            foreach ($k in $spec.Params.Keys) { $ruleParams[$k] = $spec.Params[$k] }
            New-NetFirewallRule @ruleParams | Out-Null
            $created += $spec.DisplayName
        }

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
            GpoExists    = $true
            GpoId        = $gpo.Id
            PolicyStore  = $policyStore
            BlockRules   = $created
            LinkedAtRoot = [bool]$LinkAtDomainRoot
        }
        $changeRecord.Success = $true

        Write-ADHLog -Level FIX -Message 'ADH-005 IPv6 / mitm6 mitigations - FIX applied successfully' -Console
    }
    catch {
        $changeRecord.ErrorMessage = $_.Exception.Message
        Write-ADHLog -Level ERROR -Message "ADH-005 fix failed: $($_.Exception.Message)" -Console
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
