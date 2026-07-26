#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-IPv6Mitm6.ps1')
}

Describe 'Test-IPv6Mitm6 (ADH-005)' {

    Context 'when the NetSecurity module is unavailable' {
        BeforeAll {
            Mock Get-Command -ParameterFilter { $Name -eq 'Get-NetFirewallRule' } { $null }
        }

        It 'returns Status Warning with manual-verification guidance' {
            $f = Test-IPv6Mitm6
            $f.Status   | Should -Be 'Warning'
            $f.CheckId  | Should -Be 'ADH-005'
            $f.AutoFixAvailable | Should -BeFalse
            $f.RemediationSteps | Should -Match 'RA Guard'
        }
    }

    Context 'when no GPO blocks the relevant flows' {
        BeforeAll {
            Mock Get-Command -ParameterFilter { $Name -eq 'Get-NetFirewallRule' } {
                [pscustomobject]@{ Name = 'Get-NetFirewallRule' }
            }
            Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.example.com' } }
            Mock Get-GPO { @([pscustomobject]@{
                Id = [guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                DisplayName = 'Default Domain Policy'
            }) }
            # No firewall rules in any policy store.
            Mock Get-NetFirewallRule { @() }
        }

        It 'returns Status Fail listing both missing protections' {
            $f = Test-IPv6Mitm6
            $f.Status                                | Should -Be 'Fail'
            $f.Evidence.UDP546RulesFound.Count       | Should -Be 0
            $f.Evidence.ICMPv6Type134RulesFound.Count| Should -Be 0
            $f.Description                           | Should -Match 'UDP 546'
            $f.Description                           | Should -Match 'ICMPv6 Type 134'
        }
    }

    Context 'when a GPO blocks inbound UDP 546 and ICMPv6 134 but NOT outbound DHCPv6' {
        BeforeAll {
            Mock Get-Command -ParameterFilter { $Name -eq 'Get-NetFirewallRule' } {
                [pscustomobject]@{ Name = 'Get-NetFirewallRule' }
            }
            Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.example.com' } }
            Mock Get-GPO { @([pscustomobject]@{
                Id = [guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                DisplayName = 'Invoke-ADHardening Hardening'
            }) }
            Mock Get-NetFirewallRule {
                @(
                    [pscustomobject]@{ DisplayName = 'Block DHCPv6'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Block'; InstanceID = 'r-udp546' }
                    [pscustomobject]@{ DisplayName = 'Block RA';     Enabled = 'True'; Direction = 'Inbound'; Action = 'Block'; InstanceID = 'r-ra' }
                )
            }
            Mock Get-NetFirewallPortFilter {
                if ($AssociatedNetFirewallRule.InstanceID -eq 'r-udp546') {
                    [pscustomobject]@{ Protocol = 'UDP'; LocalPort = @('546'); RemotePort = @(); IcmpType = $null }
                } else {
                    [pscustomobject]@{ Protocol = 'ICMPv6'; LocalPort = @(); RemotePort = @(); IcmpType = @('134') }
                }
            }
        }

        It 'returns Fail because the outbound DHCPv6 block is missing' {
            $f = Test-IPv6Mitm6
            $f.Status                                      | Should -Be 'Fail'
            @($f.Evidence.UDP546RulesFound).Count          | Should -Be 1
            @($f.Evidence.ICMPv6Type134RulesFound).Count   | Should -Be 1
            @($f.Evidence.UDP546OutboundRulesFound).Count  | Should -Be 0
            $f.Description                                 | Should -Match 'Outbound'
            $f.AutoFixAvailable                            | Should -BeTrue
            $f.FixFunction                                 | Should -Be 'Set-IPv6Mitm6Mitigated'
        }
    }

    Context 'when a GPO blocks all three mitm6 flows' {
        BeforeAll {
            Mock Get-Command -ParameterFilter { $Name -eq 'Get-NetFirewallRule' } {
                [pscustomobject]@{ Name = 'Get-NetFirewallRule' }
            }
            Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.example.com' } }
            Mock Get-GPO { @([pscustomobject]@{
                Id = [guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                DisplayName = 'Invoke-ADHardening Hardening'
            }) }
            Mock Get-NetFirewallRule {
                @(
                    [pscustomobject]@{ DisplayName = 'Block DHCPv6-In';  Enabled = 'True'; Direction = 'Inbound';  Action = 'Block'; InstanceID = 'r-udp546in' }
                    [pscustomobject]@{ DisplayName = 'Block RA';         Enabled = 'True'; Direction = 'Inbound';  Action = 'Block'; InstanceID = 'r-ra' }
                    [pscustomobject]@{ DisplayName = 'Block DHCPv6-Out'; Enabled = 'True'; Direction = 'Outbound'; Action = 'Block'; InstanceID = 'r-udp546out' }
                )
            }
            Mock Get-NetFirewallPortFilter {
                switch ($AssociatedNetFirewallRule.InstanceID) {
                    'r-udp546in'  { [pscustomobject]@{ Protocol = 'UDP';    LocalPort = @('546'); RemotePort = @();      IcmpType = $null } }
                    'r-ra'        { [pscustomobject]@{ Protocol = 'ICMPv6'; LocalPort = @();      RemotePort = @();      IcmpType = @('134') } }
                    'r-udp546out' { [pscustomobject]@{ Protocol = 'UDP';    LocalPort = @('546'); RemotePort = @('547'); IcmpType = $null } }
                }
            }
        }

        It 'detects all three rules and returns Pass (GPO fallback fully present)' {
            $f = Test-IPv6Mitm6
            $f.Status                                      | Should -Be 'Pass'
            @($f.Evidence.UDP546RulesFound).Count          | Should -Be 1
            @($f.Evidence.ICMPv6Type134RulesFound).Count   | Should -Be 1
            @($f.Evidence.UDP546OutboundRulesFound).Count  | Should -Be 1
            $f.AutoFixAvailable                            | Should -BeTrue
            $f.FixFunction                                 | Should -Be 'Set-IPv6Mitm6Mitigated'
        }
    }

    Context 'when Get-ADDomain throws' {
        BeforeAll {
            Mock Get-Command -ParameterFilter { $Name -eq 'Get-NetFirewallRule' } {
                [pscustomobject]@{ Name = 'Get-NetFirewallRule' }
            }
            Mock Get-ADDomain { throw 'AD unreachable' }
        }

        It 'returns Status Error' {
            $f = Test-IPv6Mitm6
            $f.Status | Should -Be 'Error'
        }
    }
}
