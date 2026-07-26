#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/Get-ADHGpoSettingForOu.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-LDAPSigning.ps1')

    function New-FakeDomain {
        [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=example,DC=com' }
    }

    # One GPO-definition row as Get-ADHGpoSettingForOu would emit it.
    function New-GpoDef([int]$Value, [string]$Name = 'DC Hardening') {
        [pscustomobject]@{
            GpoName     = $Name
            GpoId       = [guid]::NewGuid()
            OuDN        = 'OU=Domain Controllers,DC=corp,DC=example,DC=com'
            Value       = $Value
            Source      = 'SecurityOption'
            LinkEnabled = $true
        }
    }
}

Describe 'Test-LDAPSigning (ADH-004)' {

    Context 'when GPO enforces both values = 2' {
        BeforeAll {
            Mock Get-ADDomain { New-FakeDomain }
            Mock Get-ADHGpoSettingForOu { @(New-GpoDef 2) }
        }

        It 'returns Status Pass' {
            $f = Test-LDAPSigning
            $f.Status                                    | Should -Be 'Pass'
            $f.CheckId                                   | Should -Be 'ADH-004'
            $f.Severity                                  | Should -Be 'Critical'
            $f.Evidence.LDAPServerIntegrity.Effective       | Should -Be 2
            $f.Evidence.LdapEnforceChannelBinding.Effective | Should -Be 2
        }
    }

    Context 'when signing is enforced but channel binding is not configured' {
        BeforeAll {
            Mock Get-ADDomain { New-FakeDomain }
            Mock Get-ADHGpoSettingForOu -ParameterFilter { $ValueName -eq 'LDAPServerIntegrity' } { @(New-GpoDef 2) }
            Mock Get-ADHGpoSettingForOu -ParameterFilter { $ValueName -eq 'LdapEnforceChannelBinding' } { @() }
        }

        It 'returns Status Fail naming the gap and offering the fix' {
            $f = Test-LDAPSigning
            $f.Status            | Should -Be 'Fail'
            $f.AffectedObjects   | Should -Contain 'OU=Domain Controllers,DC=corp,DC=example,DC=com'
            $f.AutoFixAvailable  | Should -BeTrue
            $f.FixFunction       | Should -Be 'Set-LDAPSigningEnforced'
            ($f.Evidence.Problems -join ' ') | Should -Match 'LdapEnforceChannelBinding'
        }
    }

    Context 'when no applicable GPO configures either value' {
        BeforeAll {
            Mock Get-ADDomain { New-FakeDomain }
            Mock Get-ADHGpoSettingForOu { @() }
        }

        It 'returns Status Fail (defaults stand)' {
            $f = Test-LDAPSigning
            $f.Status                                       | Should -Be 'Fail'
            $f.Evidence.LDAPServerIntegrity.Effective       | Should -BeNullOrEmpty
            $f.Evidence.LdapEnforceChannelBinding.Effective | Should -BeNullOrEmpty
        }
    }

    Context 'when a GPO sets a non-enforcing value' {
        BeforeAll {
            Mock Get-ADDomain { New-FakeDomain }
            Mock Get-ADHGpoSettingForOu -ParameterFilter { $ValueName -eq 'LDAPServerIntegrity' } { @(New-GpoDef 1) }
            Mock Get-ADHGpoSettingForOu -ParameterFilter { $ValueName -eq 'LdapEnforceChannelBinding' } { @(New-GpoDef 2) }
        }

        It 'returns Status Fail reporting the actual value' {
            $f = Test-LDAPSigning
            $f.Status | Should -Be 'Fail'
            ($f.Evidence.Problems -join ' ') | Should -Match 'effective value is 1'
        }
    }

    Context 'when two GPOs define the same value (regression: multi-row effective-value cast)' {
        # Get-ADHGpoSettingForOu returns rows in GPO precedence order, so the
        # FIRST row is effective (see Test-LDAPSigning's docstring). This
        # mimics the live scenario that crashed: ADH-004 remediation adds a
        # second GPO ("Invoke-ADHardening DC Hardening") alongside the
        # existing "Default Domain Controllers Policy", so the check receives
        # a 2-row array instead of 1. Before the return-,$results fix, the
        # caller's @() wrap collapsed this into ONE element that was itself
        # the row array, making $row.Value an Object[] and blowing up the
        # [int] cast below with "Cannot convert System.Object[] to
        # System.Int32". This asserts the check's [int]$defs[0].Value path
        # tolerates (and correctly resolves) a genuine multi-row result.
        BeforeAll {
            Mock Get-ADDomain { New-FakeDomain }
            Mock Get-ADHGpoSettingForOu -ParameterFilter { $ValueName -eq 'LDAPServerIntegrity' } {
                @(
                    (New-GpoDef 2 'Invoke-ADHardening DC Hardening'),
                    (New-GpoDef 1 'Default Domain Controllers Policy')
                )
            }
            Mock Get-ADHGpoSettingForOu -ParameterFilter { $ValueName -eq 'LdapEnforceChannelBinding' } {
                @(
                    (New-GpoDef 2 'Invoke-ADHardening DC Hardening'),
                    (New-GpoDef 1 'Default Domain Controllers Policy')
                )
            }
        }

        It 'casts the effective (highest-precedence) value without throwing and returns Status Pass' {
            { Test-LDAPSigning } | Should -Not -Throw

            $f = Test-LDAPSigning
            $f.Status                                        | Should -Be 'Pass'
            $f.Evidence.LDAPServerIntegrity.Effective         | Should -Be 2
            $f.Evidence.LdapEnforceChannelBinding.Effective   | Should -Be 2
            $f.Evidence.LDAPServerIntegrity.Definitions.Count | Should -Be 2
        }
    }

    Context 'when Get-ADDomain throws' {
        BeforeAll {
            Mock Get-ADDomain { throw 'AD unreachable' }
        }

        It 'returns Status Error' {
            $f = Test-LDAPSigning
            $f.Status | Should -Be 'Error'
        }
    }
}
