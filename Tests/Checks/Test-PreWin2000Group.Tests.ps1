#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-PreWin2000Group.ps1')

    function New-FakeMember {
        param([string]$Name, [string]$SidValue, [string]$Class = 'group')
        [pscustomobject]@{
            Name           = $Name
            SamAccountName = $Name
            SID            = [pscustomobject]@{ Value = $SidValue }
            objectClass    = $Class
        }
    }
}

Describe 'Test-PreWin2000Group (ADH-006)' {

    Context 'when membership is clean' {
        BeforeAll {
            Mock Get-ADGroup { [pscustomobject]@{ Name = 'Pre-Windows 2000 Compatible Access' } }
            Mock Get-ADGroupMember { @(New-FakeMember -Name 'BUILTIN\Some-Innocuous' -SidValue 'S-1-5-32-545') }
        }

        It 'returns Status Pass' {
            $f = Test-PreWin2000Group
            $f.Status                            | Should -Be 'Pass'
            $f.CheckId                           | Should -Be 'ADH-006'
            $f.Evidence.ProblematicMembers.Count | Should -Be 0
        }
    }

    Context 'when Anonymous Logon is a member' {
        BeforeAll {
            Mock Get-ADGroup { [pscustomobject]@{ Name = 'Pre-Windows 2000 Compatible Access' } }
            Mock Get-ADGroupMember {
                @(
                    New-FakeMember -Name 'Anonymous Logon' -SidValue 'S-1-5-7'
                    New-FakeMember -Name 'BUILTIN\Users'    -SidValue 'S-1-5-32-545'
                )
            }
        }

        It 'returns Status Fail with auto-fix available' {
            $f = Test-PreWin2000Group
            $f.Status               | Should -Be 'Fail'
            $f.AffectedObjects      | Should -Contain 'S-1-5-7'
            $f.AutoFixAvailable     | Should -BeTrue
            $f.FixFunction          | Should -Be 'Set-PreWin2000GroupCleaned'
        }
    }

    Context 'when only Authenticated Users is present (legacy-app case)' {
        BeforeAll {
            Mock Get-ADGroup { [pscustomobject]@{ Name = 'Pre-Windows 2000 Compatible Access' } }
            Mock Get-ADGroupMember {
                @(New-FakeMember -Name 'Authenticated Users' -SidValue 'S-1-5-11')
            }
        }

        It 'returns Status Warning, NOT auto-fixable (legacy-app risk)' {
            $f = Test-PreWin2000Group
            $f.Status               | Should -Be 'Warning'
            $f.AutoFixAvailable     | Should -BeFalse
            $f.AffectedObjects      | Should -Contain 'S-1-5-11'
        }
    }

    Context 'when Get-ADGroup throws' {
        BeforeAll {
            Mock Get-ADGroup { throw 'group not found' }
        }

        It 'returns Status Error' {
            $f = Test-PreWin2000Group
            $f.Status | Should -Be 'Error'
        }
    }
}
