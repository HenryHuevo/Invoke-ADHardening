#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-ADCSMisconfig.ps1')

    function New-FakeRootDSE {
        [pscustomobject]@{ configurationNamingContext = 'CN=Configuration,DC=corp,DC=example,DC=com' }
    }

    function New-FakeCaObject {
        @([pscustomobject]@{
            cn                = 'CORP-CA'
            dNSHostName       = 'ca01.corp.example.com'
            DistinguishedName = 'CN=CORP-CA,CN=Enrollment Services,...'
        })
    }

    function New-FakeLocksmithModule {
        @([pscustomobject]@{ Name = 'Locksmith'; Version = [version]'2026.1.4.1426' })
    }
}

Describe 'Test-ADCSMisconfig (ADH-010)' {

    Context 'when AD CS is not installed (no pKIEnrollmentService objects)' {
        BeforeAll {
            Mock Get-ADRootDSE { New-FakeRootDSE }
            Mock Get-ADObject  { $null }
        }

        It 'returns Status NotApplicable' {
            $f = Test-ADCSMisconfig
            $f.Status   | Should -Be 'NotApplicable'
            $f.CheckId  | Should -Be 'ADH-010'
        }
    }

    Context 'when a CA exists but Locksmith is not installed' {
        BeforeAll {
            Mock Get-ADRootDSE { New-FakeRootDSE }
            Mock Get-ADObject { New-FakeCaObject }
            Mock Get-Module -ParameterFilter { $Name -eq 'Locksmith' } { $null }
        }

        It 'returns Status Warning pointing at Install-Module' {
            $f = Test-ADCSMisconfig
            $f.Status                       | Should -Be 'Warning'
            $f.RemediationSteps             | Should -Match 'Install-Module'
            $f.Evidence.LocksmithAvailable  | Should -BeFalse
            $f.AffectedObjects              | Should -Contain 'ca01.corp.example.com'
        }
    }

    Context 'when Get-ADRootDSE throws' {
        BeforeAll {
            Mock Get-ADRootDSE { throw 'AD unreachable' }
        }

        It 'returns Status Error' {
            $f = Test-ADCSMisconfig
            $f.Status | Should -Be 'Error'
        }
    }

    Context 'when Locksmith Mode 2 writes a CSV with issue rows' {
        BeforeAll {
            Mock Get-ADRootDSE { New-FakeRootDSE }
            Mock Get-ADObject { New-FakeCaObject }
            Mock Get-Module -ParameterFilter { $Name -eq 'Locksmith' } { New-FakeLocksmithModule }
            Mock Import-Module -ParameterFilter { $Name -eq 'Locksmith' } { }

            $script:ADHLogPath = $TestDrive

            Mock Invoke-Locksmith -ParameterFilter { $Mode -eq 2 } {
                $rows = @(
                    [pscustomobject]@{ Forest = 'corp.example.com'; Technique = 'ESC1'; Name = 'Tmpl1'; Issue = 'SAN + no approval'; Risk = 'Critical' }
                    [pscustomobject]@{ Forest = 'corp.example.com'; Technique = 'ESC4'; Name = 'Tmpl1'; Issue = 'Owner can reconfigure'; Risk = 'Low' }
                    [pscustomobject]@{ Forest = 'corp.example.com'; Technique = 'ESC15/EKUwu'; Name = 'User'; Issue = 'Application policy bypass'; Risk = 'High' }
                )
                $rows | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath 'Locksmith 2026-07-12 00-00-00 ADCSIssues.CSV')
            }
        }

        It 'returns Status Fail with the real row count in Evidence' {
            $f = Test-ADCSMisconfig
            $f.Status                        | Should -Be 'Fail'
            $f.Evidence.LocksmithRawCount    | Should -Be 3
            $f.Evidence.LocksmithFindings.Count | Should -Be 3
            $f.Evidence.LocksmithCsvFile     | Should -Be 'Locksmith 2026-07-12 00-00-00 ADCSIssues.CSV'
            $f.Description                   | Should -Match '3 AD CS finding'
            $f.AffectedObjects               | Should -Contain 'ca01.corp.example.com'
        }
    }

    Context 'when Locksmith Mode 2 writes a CSV with zero rows (affirmatively clean)' {
        BeforeAll {
            Mock Get-ADRootDSE { New-FakeRootDSE }
            Mock Get-ADObject { New-FakeCaObject }
            Mock Get-Module -ParameterFilter { $Name -eq 'Locksmith' } { New-FakeLocksmithModule }
            Mock Import-Module -ParameterFilter { $Name -eq 'Locksmith' } { }

            $script:ADHLogPath = $TestDrive

            Mock Invoke-Locksmith -ParameterFilter { $Mode -eq 2 } {
                # Real Locksmith always creates the file via Export-Csv even
                # when zero objects are piped through it - an empty file.
                New-Item -ItemType File -Path (Join-Path $OutputPath 'Locksmith 2026-07-12 00-01-00 ADCSIssues.CSV') -Force | Out-Null
            }
        }

        It 'returns Status Pass' {
            $f = Test-ADCSMisconfig
            $f.Status                     | Should -Be 'Pass'
            $f.Evidence.LocksmithRawCount | Should -Be 0
        }
    }

    Context 'when Invoke-Locksmith throws' {
        BeforeAll {
            Mock Get-ADRootDSE { New-FakeRootDSE }
            Mock Get-ADObject { New-FakeCaObject }
            Mock Get-Module -ParameterFilter { $Name -eq 'Locksmith' } { New-FakeLocksmithModule }
            Mock Import-Module -ParameterFilter { $Name -eq 'Locksmith' } { }

            $script:ADHLogPath = $TestDrive

            Mock Invoke-Locksmith -ParameterFilter { $Mode -eq 2 } { throw 'Locksmith blew up' }
        }

        It 'returns Status Warning, never Pass' {
            $f = Test-ADCSMisconfig
            $f.Status              | Should -Be 'Warning'
            $f.Evidence.LocksmithError | Should -Match 'Locksmith blew up'
        }
    }

    Context 'when Locksmith runs without error but writes no CSV at all' {
        BeforeAll {
            Mock Get-ADRootDSE { New-FakeRootDSE }
            Mock Get-ADObject { New-FakeCaObject }
            Mock Get-Module -ParameterFilter { $Name -eq 'Locksmith' } { New-FakeLocksmithModule }
            Mock Import-Module -ParameterFilter { $Name -eq 'Locksmith' } { }

            $script:ADHLogPath = $TestDrive

            # Simulates Locksmith swallowing an internal error (its own
            # try/catch around Export-Csv) without throwing to us.
            Mock Invoke-Locksmith -ParameterFilter { $Mode -eq 2 } { }
        }

        It 'returns Status Warning, never Pass' {
            $f = Test-ADCSMisconfig
            $f.Status      | Should -Be 'Warning'
            $f.Description | Should -Match 'produced no ADCSIssues.CSV'
        }
    }

    Context 'when the installed Locksmith does not support -OutputPath (older version)' {
        BeforeAll {
            Mock Get-ADRootDSE { New-FakeRootDSE }
            Mock Get-ADObject { New-FakeCaObject }
            Mock Get-Module -ParameterFilter { $Name -eq 'Locksmith' } { New-FakeLocksmithModule }
            Mock Import-Module -ParameterFilter { $Name -eq 'Locksmith' } { }

            $script:ADHLogPath = $TestDrive

            # Override the stub with a signature that has no OutputPath
            # parameter, simulating a pre-structured-output Locksmith.
            function Invoke-Locksmith { [CmdletBinding()]param($Mode, [Parameter(ValueFromRemainingArguments)]$Rest) }
        }

        AfterAll {
            # Restore the full stub so later test files/contexts aren't affected.
            . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
        }

        It 'returns Status Warning, never a fake Pass' {
            $f = Test-ADCSMisconfig
            $f.Status      | Should -Be 'Warning'
            $f.Description | Should -Match 'does not support structured output capture'
        }
    }

    Context 'when the run report directory is not available' {
        BeforeAll {
            Mock Get-ADRootDSE { New-FakeRootDSE }
            Mock Get-ADObject { New-FakeCaObject }
            Mock Get-Module -ParameterFilter { $Name -eq 'Locksmith' } { New-FakeLocksmithModule }
            Mock Import-Module -ParameterFilter { $Name -eq 'Locksmith' } { }

            $script:ADHLogPath = $null
        }

        It 'returns Status Warning without invoking Locksmith' {
            Mock Invoke-Locksmith { throw 'should not be called' }

            $f = Test-ADCSMisconfig
            $f.Status | Should -Be 'Warning'
            Should -Invoke Invoke-Locksmith -Times 0
        }
    }
}
