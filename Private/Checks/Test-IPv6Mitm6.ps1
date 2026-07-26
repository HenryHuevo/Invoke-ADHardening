function Test-IPv6Mitm6 {
    <#
    .SYNOPSIS
        ADH-005 - Verifies mitm6 / rogue-DHCPv6 mitigations are in place.
    .DESCRIPTION
        mitm6 abuses Windows' default IPv6 preference: every host comes up
        with IPv6 enabled, every host accepts DHCPv6 from any link-local
        responder, and once you control DNS via DHCPv6 you can relay onto
        anything. The best mitigation is switch-level RA Guard + DHCPv6
        Guard, which we cannot detect from this audit context - we can
        only check the second-best fallback: Windows Firewall rules
        blocking the three relevant flows on every host:

          - Inbound  UDP 546        (DHCPv6 client)
          - Inbound  ICMPv6 Type 134 (IPv6 Router Advertisement)
          - Outbound UDP 546 -> 547  (DHCPv6 client)

        This DOES inspect Group Policy. The reason it uses the NetSecurity
        module rather than the Get-GP* / Get-ADHGpoSettingForOu path that the
        other GPO-based checks use is that firewall rules are not stored in a
        GPO the way Administrative-Template or Security-Option settings are:
        they live in an MSFT_NetFirewallRule WMI store, not registry.pol or
        GptTmpl.inf. The only supported way to read a GPO's firewall rules is
        Get-NetFirewallRule -PolicyStore "<domain>\<gpoDisplayName>", which is
        exactly what this check does for every GPO in the domain. So
        Get-GPRegistryValue / Get-GPOReport cannot see these rules; NetSecurity
        is the GPO-reading API here, not an endpoint-querying one.

        NetSecurity ships in-box on Windows 8/Server 2012 and later (including
        every DC), so it is normally present. If it is genuinely missing we
        degrade gracefully to Warning + manual-verification guidance.

        Auto-fix (Set-IPv6Mitm6Mitigated) creates exactly these three Block
        rules in the Invoke-ADHardening Hardening GPO. A Pass therefore means
        the GPO-based host fallback is fully in place - it does NOT prove the
        preferred switch-level RA/DHCPv6 Guard is configured (see Limitations).
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-005 IPv6 / mitm6 mitigations - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-005'
        CheckName  = 'IPv6 / mitm6 Mitigations'
        Category   = 'Relay Defenses'
        Severity   = 'High'
        References = @(
            'https://github.com/dirkjanm/mitm6',
            'https://www.fox-it.com/nl-en/blog/mitm6-compromising-ipv4-networks-via-ipv6/',
            'https://learn.microsoft.com/en-us/windows-server/networking/technologies/ipv6/ipv6-troubleshooting',
            'MITRE ATT&CK T1557.002'
        )
    }

    $remediation = @"
Preferred (switch/network): enable IPv6 First-Hop Security on access switches
  - RA Guard (block rogue Router Advertisements)
  - DHCPv6 Guard (block rogue DHCPv6 servers)
These cannot be audited from AD - confirm with your network team.

Fallback (Windows Firewall via GPO - this is what Set-IPv6Mitm6Mitigated
automates): create firewall rules on the Invoke-ADHardening Hardening GPO
that BLOCK:
  - Inbound  UDP 546         (DHCPv6 client - DHCPV6-In)
  - Inbound  ICMPv6 Type 134 (Router Advertisement - ICMPv6-In)
  - Outbound UDP 546 -> 547   (DHCPv6 client - DHCPV6-Out)

Do not disable IPv6 with the DisabledComponents registry value; Microsoft
documents that as unsupported on modern Windows and it has caused real
production outages.
"@

    $evidence = @{
        AuditMethod        = 'GPO firewall-rule enumeration via Get-NetFirewallRule -PolicyStore "<domain>\<gpo>" (the only API that reads firewall rules out of a GPO; they are not registry.pol/GptTmpl-backed, so Get-GPRegistryValue/Get-GPOReport cannot see them).'
        RequiresElevation  = $false
        Limitations        = 'This audit cannot detect switch-level RA Guard / DHCPv6 Guard - those are the preferred mitigation and live on the network gear, not AD. A Pass below only means the GPO-based host firewall fallback (all three Block rules) is present, not that switch-level guards are configured.'
        UDP546RulesFound        = @()
        ICMPv6Type134RulesFound = @()
        UDP546OutboundRulesFound = @()
        ScanErrors         = @()
    }

    try {
        if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
            $evidence.Limitations += ' Get-NetFirewallRule (NetSecurity module) is unavailable here, so GPO firewall rules could not be read. NetSecurity is in-box on Server 2012+/Windows 8+; run this from a DC or a management host with RSAT to get a definitive result.'
            $finding = New-ADHFinding @checkParams `
                -Status 'Warning' `
                -Description 'Cannot read GPO firewall rules because Get-NetFirewallRule (NetSecurity) is unavailable on this host - not because no GPOs were checked. NetSecurity is the only API that exposes a GPO''s firewall rules. Re-run from a DC / RSAT host, or verify mitm6 mitigations manually.' `
                -Evidence $evidence `
                -RemediationSteps $remediation `
                -AutoFixAvailable $false

            Write-ADHLog -Level WARN -Message 'ADH-005 IPv6 mitm6 - WARN (NetSecurity unavailable)' -Console
            return $finding
        }

        $domain = Get-ADDomain -ErrorAction Stop
        $dnsRoot = $domain.DNSRoot
        $allGpos = Get-GPO -All -ErrorAction Stop

        foreach ($gpo in $allGpos) {
            $policyStore = "$dnsRoot\$($gpo.DisplayName)"
            try {
                $rules = Get-NetFirewallRule -PolicyStore $policyStore -ErrorAction Stop |
                    Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and
                                   ($_.Direction -eq 'Inbound' -or $_.Direction -eq 'Outbound') }

                foreach ($rule in $rules) {
                    # Protocol/port/ICMP type all come off the port filter; there
                    # is no Get-NetFirewallProtocol cmdlet (calling it threw on
                    # every rule and the scan silently found nothing).
                    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                    $isUdp      = ($portFilter.Protocol -eq 'UDP')

                    # Inbound DHCPv6 client: UDP local port 546.
                    $isUdp546In  = $isUdp -and ($rule.Direction -eq 'Inbound')  -and ($portFilter.LocalPort -contains '546')
                    # Outbound DHCPv6 client: UDP local 546 or remote 547.
                    $isUdp546Out = $isUdp -and ($rule.Direction -eq 'Outbound') -and
                                   (($portFilter.LocalPort -contains '546') -or ($portFilter.RemotePort -contains '547'))

                    # Inbound ICMPv6 Router Advertisement: protocol ICMPv6, type 134.
                    $isRa = $false
                    if ($rule.Direction -eq 'Inbound' -and $portFilter -and $portFilter.IcmpType) {
                        $isRa = ($portFilter.IcmpType -contains '134') -or ($portFilter.IcmpType -contains '134:*')
                    }

                    $info = [PSCustomObject]@{
                        GPO        = $gpo.DisplayName
                        RuleName   = $rule.DisplayName
                        Direction  = $rule.Direction
                        Protocol   = $portFilter.Protocol
                        LocalPort  = ($portFilter.LocalPort -join ',')
                        RemotePort = ($portFilter.RemotePort -join ',')
                        IcmpType   = if ($portFilter) { ($portFilter.IcmpType -join ',') } else { '' }
                    }
                    if ($isUdp546In)  { $evidence.UDP546RulesFound += $info }
                    if ($isUdp546Out) { $evidence.UDP546OutboundRulesFound += $info }
                    if ($isRa)        { $evidence.ICMPv6Type134RulesFound += $info }
                }
            }
            catch {
                # Most GPOs won't have firewall policy - that's not an error, just empty store.
                if ($_.Exception.Message -notmatch 'No MSFT_NetFirewallRule|cannot find an object') {
                    $evidence.ScanErrors += "GPO '$($gpo.DisplayName)': $($_.Exception.Message)"
                }
            }
        }

        $hasUdp546In  = $evidence.UDP546RulesFound.Count -gt 0
        $hasRa        = $evidence.ICMPv6Type134RulesFound.Count -gt 0
        $hasUdp546Out = $evidence.UDP546OutboundRulesFound.Count -gt 0

        if ($hasUdp546In -and $hasRa -and $hasUdp546Out) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description 'GPO firewall rules block all three mitm6 flows: inbound DHCPv6 (UDP 546), inbound Router Advertisement (ICMPv6 Type 134), and outbound DHCPv6 (UDP 546->547). This is the host-level GPO fallback - the preferred mitigation is switch-level RA Guard + DHCPv6 Guard, which cannot be audited here.' `
                -Evidence $evidence `
                -RemediationSteps $remediation `
                -AutoFixAvailable $true `
                -FixFunction 'Set-IPv6Mitm6Mitigated'

            Write-ADHLog -Level PASS -Message 'ADH-005 IPv6 mitm6 - PASS (all 3 GPO Block rules present; switch-level cannot be verified)' -Console
        }
        else {
            $missing = @()
            if (-not $hasUdp546In)  { $missing += 'Inbound UDP 546 (DHCPv6 client)' }
            if (-not $hasRa)        { $missing += 'Inbound ICMPv6 Type 134 (Router Advertisement)' }
            if (-not $hasUdp546Out) { $missing += 'Outbound UDP 546->547 (DHCPv6 client)' }

            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "No GPO firewall rules block: $($missing -join '; '). Hosts will accept/solicit rogue DHCPv6 or Router Advertisements - mitm6 trivially viable. Switch-level RA/DHCPv6 Guard is preferred but cannot be verified from here." `
                -Evidence $evidence `
                -RemediationSteps $remediation `
                -AutoFixAvailable $true `
                -FixFunction 'Set-IPv6Mitm6Mitigated'

            Write-ADHLog -Level FAIL -Message "ADH-005 IPv6 mitm6 - FAIL (missing: $($missing -join ', '))" -Console
        }

        return $finding
    }
    catch {
        $evidence.ScanErrors += $_.Exception.Message
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence $evidence

        Write-ADHLog -Level ERROR -Message "ADH-005 IPv6 mitm6 - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
