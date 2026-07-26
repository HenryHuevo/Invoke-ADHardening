#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-LLMNR.ps1')
}

Describe 'Test-LLMNR (ADH-001)' {

    Context 'when a linked GPO sets EnableMulticast=0' {
        BeforeAll {
            Mock Get-GPO { @([pscustomobject]@{
                Id          = [guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                DisplayName = 'Disable LLMNR'
            }) }
            Mock Get-GPRegistryValue { [pscustomobject]@{ Value = 0 } }
            Mock Get-GPOReport {
                '<GPO><LinksTo><SOMPath>corp.example.com</SOMPath><Enabled>true</Enabled></LinksTo></GPO>'
            }
        }

        It 'returns Status Pass' {
            $f = Test-LLMNR
            $f.Status   | Should -Be 'Pass'
            $f.CheckId  | Should -Be 'ADH-001'
            $f.Severity | Should -Be 'High'
            $f.Evidence.MatchingGPOs.Count | Should -BeGreaterThan 0
        }
    }

    Context 'when no GPO defines EnableMulticast' {
        BeforeAll {
            Mock Get-GPO { @([pscustomobject]@{
                Id          = [guid]'11111111-2222-3333-4444-555555555555'
                DisplayName = 'Some Other GPO'
            }) }
            Mock Get-GPRegistryValue { throw [System.ArgumentException]::new('value not present') }
        }

        It 'returns Status Fail with auto-fix available' {
            $f = Test-LLMNR
            $f.Status           | Should -Be 'Fail'
            $f.AutoFixAvailable | Should -BeTrue
            $f.FixFunction      | Should -Be 'Set-LLMNRDisabled'
        }
    }

    Context 'when Get-GPO throws' {
        BeforeAll {
            Mock Get-GPO { throw 'access denied' }
        }

        It 'returns Status Error' {
            $f = Test-LLMNR
            $f.Status | Should -Be 'Error'
            $f.Evidence.Exception | Should -Match 'access denied'
        }
    }
}
