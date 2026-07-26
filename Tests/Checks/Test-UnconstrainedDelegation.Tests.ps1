#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-UnconstrainedDelegation.ps1')
}

Describe 'Test-UnconstrainedDelegation (ADH-008)' {

    Context 'when no non-DC computers or users have unconstrained delegation' {
        BeforeAll {
            Mock Get-ADComputer { @() }
            Mock Get-ADUser     { @() }
        }

        It 'returns Status Pass' {
            $f = Test-UnconstrainedDelegation
            $f.Status            | Should -Be 'Pass'
            $f.CheckId           | Should -Be 'ADH-008'
            $f.Severity          | Should -Be 'Critical'
            $f.Evidence.Computers.Count | Should -Be 0
            $f.Evidence.Users.Count     | Should -Be 0
        }
    }

    Context 'when a non-DC computer trusts unconstrained delegation' {
        BeforeAll {
            Mock Get-ADComputer {
                @([pscustomobject]@{
                    Name              = 'FILE01'
                    DNSHostName       = 'file01.corp.example.com'
                    OperatingSystem   = 'Windows Server 2019'
                    Enabled           = $true
                    LastLogonDate     = (Get-Date).AddDays(-1)
                    DistinguishedName = 'CN=FILE01,OU=Servers,DC=corp,DC=example,DC=com'
                })
            }
            Mock Get-ADUser { @() }
        }

        It 'returns Status Fail flagging the computer' {
            $f = Test-UnconstrainedDelegation
            $f.Status                    | Should -Be 'Fail'
            $f.Evidence.Computers.Count  | Should -Be 1
            $f.AffectedObjects           | Should -Contain 'file01.corp.example.com'
            $f.AutoFixAvailable          | Should -BeFalse  # guidance-only
        }
    }

    Context 'when a user has TrustedForDelegation' {
        BeforeAll {
            Mock Get-ADComputer { @() }
            Mock Get-ADUser {
                @([pscustomobject]@{
                    SamAccountName    = 'legacy-svc'
                    Enabled           = $true
                    LastLogonDate     = (Get-Date).AddDays(-7)
                    AdminCount        = 1
                    MemberOf          = @()
                    DistinguishedName = 'CN=legacy-svc,CN=Users,DC=corp,DC=example,DC=com'
                })
            }
        }

        It 'returns Status Fail flagging the user' {
            $f = Test-UnconstrainedDelegation
            $f.Status                | Should -Be 'Fail'
            $f.Evidence.Users.Count  | Should -Be 1
            $f.AffectedObjects       | Should -Contain 'legacy-svc'
        }
    }

    Context 'when Get-ADComputer throws' {
        BeforeAll {
            Mock Get-ADComputer { throw 'AD unreachable' }
        }

        It 'returns Status Error' {
            $f = Test-UnconstrainedDelegation
            $f.Status | Should -Be 'Error'
        }
    }
}
