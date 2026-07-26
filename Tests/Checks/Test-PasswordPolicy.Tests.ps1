#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-PasswordPolicy.ps1')

    function New-FakePolicy {
        param(
            [int]$MinLen        = 14,
            [int]$LockoutThr    = 5,
            [int]$LockoutMin    = 30,
            [int]$MaxAgeDays    = 90,
            [bool]$Complex      = $true
        )
        [pscustomobject]@{
            MinPasswordLength    = $MinLen
            LockoutThreshold     = $LockoutThr
            LockoutDuration      = [timespan]::FromMinutes($LockoutMin)
            MaxPasswordAge       = [timespan]::FromDays($MaxAgeDays)
            MinPasswordAge       = [timespan]::FromDays(1)
            PasswordHistoryCount = 24
            ComplexityEnabled    = $Complex
        }
    }
}

Describe 'Test-PasswordPolicy (ADH-009)' {

    BeforeEach {
        # Default: no PasswordNeverExpires users
        Mock Get-ADUser { @() }
    }

    Context 'when the policy meets every baseline condition' {
        BeforeAll {
            Mock Get-ADDefaultDomainPasswordPolicy { New-FakePolicy }
        }

        It 'returns Status Pass' {
            $f = Test-PasswordPolicy
            $f.Status                        | Should -Be 'Pass'
            $f.CheckId                       | Should -Be 'ADH-009'
            $f.Evidence.FailedConditions.Count | Should -Be 0
        }
    }

    Context 'when MinPasswordLength is below 14' {
        BeforeAll {
            Mock Get-ADDefaultDomainPasswordPolicy { New-FakePolicy -MinLen 8 }
        }

        It 'returns Status Fail and lists the failing condition' {
            $f = Test-PasswordPolicy
            $f.Status                  | Should -Be 'Fail'
            $f.AutoFixAvailable        | Should -BeTrue
            $f.FixFunction             | Should -Be 'Set-PasswordPolicyBaseline'
            ($f.Evidence.FailedConditions | ForEach-Object Setting) | Should -Contain 'MinPasswordLength'
        }
    }

    Context 'when account lockout is disabled (threshold = 0)' {
        BeforeAll {
            Mock Get-ADDefaultDomainPasswordPolicy { New-FakePolicy -LockoutThr 0 }
        }

        It 'returns Status Fail' {
            $f = Test-PasswordPolicy
            $f.Status | Should -Be 'Fail'
            ($f.Evidence.FailedConditions | ForEach-Object Setting) | Should -Contain 'LockoutThreshold'
        }
    }

    Context 'when MaxPasswordAge is 0 (never expire)' {
        BeforeAll {
            Mock Get-ADDefaultDomainPasswordPolicy { New-FakePolicy -MaxAgeDays 0 }
        }

        It 'returns Status Pass (never-expire is allowed, NIST 800-63B)' {
            $f = Test-PasswordPolicy
            $f.Status | Should -Be 'Pass'
            ($f.Evidence.FailedConditions | ForEach-Object Setting) | Should -Not -Contain 'MaxPasswordAge'
        }
    }

    Context 'when MaxPasswordAge exceeds 365 days' {
        BeforeAll {
            Mock Get-ADDefaultDomainPasswordPolicy { New-FakePolicy -MaxAgeDays 500 }
        }

        It 'returns Status Fail' {
            $f = Test-PasswordPolicy
            $f.Status | Should -Be 'Fail'
            ($f.Evidence.FailedConditions | ForEach-Object Setting) | Should -Contain 'MaxPasswordAge'
        }
    }

    Context 'when Get-ADDefaultDomainPasswordPolicy throws' {
        BeforeAll {
            Mock Get-ADDefaultDomainPasswordPolicy { throw 'no DC' }
        }

        It 'returns Status Error' {
            $f = Test-PasswordPolicy
            $f.Status | Should -Be 'Error'
        }
    }
}
