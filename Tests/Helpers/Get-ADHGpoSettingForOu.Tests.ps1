#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/Get-ADHGpoSettingForOu.ps1')

    $script:OuDN       = 'OU=Domain Controllers,DC=corp,DC=example,DC=com'
    $script:RegistryKey = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $script:ValueName   = 'LDAPServerIntegrity'

    $script:Gpo1Id = [guid]'11111111-1111-1111-1111-111111111111'
    $script:Gpo2Id = [guid]'22222222-2222-2222-2222-222222222222'

    # Security-Options XML report for a GPO that defines LDAPServerIntegrity
    # as the named Security Option (not registry.pol) with the given value.
    function New-SecOptReportXml([int]$SettingNumber) {
        @"
<GPO>
  <LinksTo><SOMPath>corp.example.com</SOMPath><Enabled>true</Enabled></LinksTo>
  <Computer><ExtensionData><Extension>
    <SecurityOptions><KeyName>MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity</KeyName><SettingNumber>$SettingNumber</SettingNumber></SecurityOptions>
  </Extension></ExtensionData></Computer>
</GPO>
"@
    }
}

Describe 'Get-ADHGpoSettingForOu' {

    Context 'when two linked GPOs both define the same Security Option value (regression)' {
        # Guards the multi-row return shape. If Get-ADHGpoSettingForOu returned
        # `,$results` (array-wrapped), the sole caller's @(...) wrap would
        # collapse two matching GPOs into a SINGLE element that is itself the
        # whole row array, making $row.Value an Object[] and breaking the
        # downstream [int] cast in Test-LDAPSigning ("Cannot convert
        # System.Object[] to System.Int32"). This exercises the REAL function (not a mock of it)
        # with two GPOs, both resolved via the Security-Options XML fallback
        # path (Get-GPRegistryValue reports "not present", forcing
        # Get-GPOReport parsing), and asserts the function returns two
        # separate row objects with scalar, [int]-castable Value properties.
        BeforeAll {
            Mock Get-GPInheritance {
                [pscustomobject]@{
                    InheritedGpoLinks = @(
                        [pscustomobject]@{ GpoId = $script:Gpo1Id; Enabled = $true },
                        [pscustomobject]@{ GpoId = $script:Gpo2Id; Enabled = $true }
                    )
                    GpoLinks = @()
                }
            }

            Mock Get-GPO -ParameterFilter { $Guid -eq $script:Gpo1Id } {
                [pscustomobject]@{ Id = $script:Gpo1Id; DisplayName = 'Default Domain Controllers Policy' }
            }
            Mock Get-GPO -ParameterFilter { $Guid -eq $script:Gpo2Id } {
                [pscustomobject]@{ Id = $script:Gpo2Id; DisplayName = 'Invoke-ADHardening DC Hardening' }
            }

            # Neither GPO expresses the value as registry.pol - force the
            # Security-Options XML fallback for both.
            Mock Get-GPRegistryValue { throw [System.ArgumentException]::new('value not present') }

            Mock Get-GPOReport -ParameterFilter { $Guid -eq $script:Gpo1Id } { New-SecOptReportXml 1 }
            Mock Get-GPOReport -ParameterFilter { $Guid -eq $script:Gpo2Id } { New-SecOptReportXml 2 }
        }

        It 'returns one row per defining GPO with scalar, [int]-castable Value properties' {
            $results = @(Get-ADHGpoSettingForOu -OuDN $script:OuDN -RegistryKey $script:RegistryKey `
                    -ValueName $script:ValueName -IncludeInherited)

            $results.Count | Should -Be 2

            $results.GpoName | Should -Contain 'Default Domain Controllers Policy'
            $results.GpoName | Should -Contain 'Invoke-ADHardening DC Hardening'

            foreach ($row in $results) {
                $row.Value | Should -BeOfType ([int])
                { [int]$row.Value } | Should -Not -Throw
            }

            ($results | Where-Object GpoName -eq 'Default Domain Controllers Policy').Value | Should -Be 1
            ($results | Where-Object GpoName -eq 'Invoke-ADHardening DC Hardening').Value | Should -Be 2
        }
    }
}
