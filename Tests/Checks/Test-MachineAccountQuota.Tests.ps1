#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-MachineAccountQuota.ps1')
}

Describe 'Test-MachineAccountQuota (ADH-002)' {

    Context 'when the quota is 0' {
        BeforeAll {
            Mock Get-ADDomain {
                [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=example,DC=com' }
            }
            Mock Get-ADObject {
                [pscustomobject]@{ 'ms-DS-MachineAccountQuota' = 0 }
            }
        }

        It 'returns Status Pass' {
            $f = Test-MachineAccountQuota
            $f.Status                              | Should -Be 'Pass'
            $f.CheckId                             | Should -Be 'ADH-002'
            $f.Evidence.MachineAccountQuotaValue   | Should -Be 0
        }
    }

    Context 'when the quota is the default 10' {
        BeforeAll {
            Mock Get-ADDomain {
                [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=example,DC=com' }
            }
            Mock Get-ADObject {
                [pscustomobject]@{ 'ms-DS-MachineAccountQuota' = 10 }
            }
        }

        It 'returns Status Fail and offers the auto-fix' {
            $f = Test-MachineAccountQuota
            $f.Status                              | Should -Be 'Fail'
            $f.AutoFixAvailable                    | Should -BeTrue
            $f.FixFunction                         | Should -Be 'Set-MachineAccountQuota'
            $f.Evidence.MachineAccountQuotaValue   | Should -Be 10
        }
    }

    Context 'when Get-ADDomain throws' {
        BeforeAll {
            Mock Get-ADDomain { throw 'no DC reachable' }
        }

        It 'returns Status Error' {
            $f = Test-MachineAccountQuota
            $f.Status | Should -Be 'Error'
        }
    }
}
