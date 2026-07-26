#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-Kerberoasting.ps1')

    function New-FakeUser {
        param(
            [string]$Sam,
            [string[]]$Spns       = @(),
            [bool]$NoPreAuth      = $false,
            [datetime]$PwdSet     = (Get-Date).AddDays(-30),
            [int]$AdminCount      = 0,
            [string[]]$MemberOf   = @()
        )
        [pscustomobject]@{
            SamAccountName        = $Sam
            ServicePrincipalName  = $Spns
            DoesNotRequirePreAuth = $NoPreAuth
            PasswordLastSet       = $PwdSet
            AdminCount            = $AdminCount
            MemberOf              = $MemberOf
        }
    }

    function New-FakeDomain {
        [pscustomobject]@{
            DomainSID = [pscustomobject]@{ Value = 'S-1-5-21-1111-2222-3333' }
        }
    }
}

Describe 'Test-Kerberoasting (ADH-007)' {

    Context 'when there are no Kerberoastable or AS-REP roastable accounts' {
        BeforeAll {
            Mock Get-ADDomain { New-FakeDomain }
            Mock Get-ADUser   { @() }
        }

        It 'returns Status Pass' {
            $f = Test-Kerberoasting
            $f.Status                   | Should -Be 'Pass'
            $f.CheckId                  | Should -Be 'ADH-007'
            $f.Evidence.Accounts.Count  | Should -Be 0
        }
    }

    Context 'when a non-privileged service account with a recent password is Kerberoastable' {
        BeforeAll {
            Mock Get-ADDomain { New-FakeDomain }
            # Single switch-on-input mock — more robust than two -ParameterFilter mocks
            # because Pester evaluates the filters cleanly regardless of -Filter type.
            Mock Get-ADUser {
                if ($Filter.ToString() -match 'ServicePrincipalName') {
                    @(New-FakeUser -Sam 'svc-sql' -Spns @('MSSQLSvc/sql01:1433'))
                } else {
                    @()
                }
            }
        }

        It 'returns Status Fail at severity High' {
            $f = Test-Kerberoasting
            $f.Status              | Should -Be 'Fail'
            $f.Severity            | Should -Be 'High'
            $f.AffectedObjects     | Should -Contain 'svc-sql'
        }
    }

    Context 'when a privileged user has an aged password (Critical escalation)' {
        BeforeAll {
            Mock Get-ADDomain { New-FakeDomain }
            Mock Get-ADUser {
                if ($Filter.ToString() -match 'ServicePrincipalName') {
                    @(New-FakeUser -Sam 'svc-old' -Spns @('HTTP/web01') `
                        -PwdSet (Get-Date).AddDays(-400) -AdminCount 1)
                } else {
                    @()
                }
            }
        }

        It 'escalates Severity to Critical' {
            $f = Test-Kerberoasting
            $f.Status   | Should -Be 'Fail'
            $f.Severity | Should -Be 'Critical'
        }
    }

    Context 'when Get-ADDomain throws' {
        BeforeAll {
            Mock Get-ADDomain { throw 'no DC' }
        }

        It 'returns Status Error' {
            $f = Test-Kerberoasting
            $f.Status | Should -Be 'Error'
        }
    }
}
