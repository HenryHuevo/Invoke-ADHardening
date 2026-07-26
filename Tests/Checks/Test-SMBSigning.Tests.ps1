#requires -Modules Pester

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../')).Path
    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Checks/Test-SMBSigning.ps1')

    # XML for a single enabled link with no Security Options. Forces the check
    # onto its registry.pol fallback path (Get-GPRegistryValue).
    $script:LinkOnlyXml = '<GPO><LinksTo><SOMPath>corp.example.com</SOMPath><Enabled>true</Enabled></LinksTo></GPO>'

    # XML where both SMB signing settings are the named Security Options.
    $script:SecOptBothXml = @'
<GPO>
  <LinksTo><SOMPath>corp.example.com</SOMPath><Enabled>true</Enabled></LinksTo>
  <Computer><ExtensionData><Extension>
    <SecurityOptions><KeyName>MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature</KeyName><SettingNumber>1</SettingNumber></SecurityOptions>
    <SecurityOptions><KeyName>MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature</KeyName><SettingNumber>1</SettingNumber></SecurityOptions>
  </Extension></ExtensionData></Computer>
</GPO>
'@

    # Shared default mocks. Kept in Describe-level BeforeAll (NOT BeforeEach) so
    # a Context's BeforeAll can override Get-GPOReport / Get-GPRegistryValue
    # without being clobbered after Context setup runs.
}

Describe 'Test-SMBSigning (ADH-003)' {

    BeforeAll {
        Mock Get-GPO { @([pscustomobject]@{
            Id          = [guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            DisplayName = 'SMB Signing'
        }) }
        # Default: link-only report (registry.pol path). Contexts override.
        Mock Get-GPOReport { $script:LinkOnlyXml }
    }

    Context 'when both sides are set as the named Security Options' {
        BeforeAll {
            Mock Get-GPOReport { $script:SecOptBothXml }
            # If the check ever fell through to registry.pol here it would be a bug;
            # make that loud.
            Mock Get-GPRegistryValue { throw [System.ArgumentException]::new('should not be called') }
        }

        It 'returns Status Pass detecting both Security Options' {
            $f = Test-SMBSigning
            $f.Status                          | Should -Be 'Pass'
            $f.Evidence.ServerSideCovered      | Should -BeTrue
            $f.Evidence.ClientSideCovered      | Should -BeTrue
            $f.Evidence.ServerSideGPOs[0].Source | Should -Be 'SecurityOption'
            $f.Evidence.ClientSideGPOs[0].Source | Should -Be 'SecurityOption'
        }
    }

    Context 'when both sides are set as registry.pol values (legacy)' {
        BeforeAll {
            Mock Get-GPRegistryValue { [pscustomobject]@{ Value = 1 } }
        }

        It 'returns Status Pass via the registry.pol fallback' {
            $f = Test-SMBSigning
            $f.Status                          | Should -Be 'Pass'
            $f.CheckId                         | Should -Be 'ADH-003'
            $f.Evidence.ServerSideCovered      | Should -BeTrue
            $f.Evidence.ClientSideCovered      | Should -BeTrue
            $f.Evidence.ServerSideGPOs[0].Source | Should -Be 'RegistryPolicy'
        }
    }

    Context 'when only the server-side is set' {
        BeforeAll {
            Mock Get-GPRegistryValue -ParameterFilter { $Key -like '*LanmanServer*' } {
                [pscustomobject]@{ Value = 1 }
            }
            Mock Get-GPRegistryValue -ParameterFilter { $Key -like '*LanmanWorkstation*' } {
                throw [System.ArgumentException]::new('value not present')
            }
        }

        It 'returns Status Fail flagging the client-side gap' {
            $f = Test-SMBSigning
            $f.Status                       | Should -Be 'Fail'
            $f.Evidence.ServerSideCovered   | Should -BeTrue
            $f.Evidence.ClientSideCovered   | Should -BeFalse
            $f.AutoFixAvailable             | Should -BeTrue
            $f.FixFunction                  | Should -Be 'Set-SMBSigningRequired'
        }
    }

    Context 'when neither side is set in any GPO' {
        BeforeAll {
            Mock Get-GPRegistryValue { throw [System.ArgumentException]::new('value not present') }
        }

        It 'returns Status Fail' {
            $f = Test-SMBSigning
            $f.Status                       | Should -Be 'Fail'
            $f.Evidence.ServerSideCovered   | Should -BeFalse
            $f.Evidence.ClientSideCovered   | Should -BeFalse
        }
    }

    Context 'when the GPO sets the values but is not linked anywhere' {
        BeforeAll {
            Mock Get-GPOReport { '<GPO><LinksTo><SOMPath>corp.example.com</SOMPath><Enabled>false</Enabled></LinksTo></GPO>' }
            Mock Get-GPRegistryValue { [pscustomobject]@{ Value = 1 } }
        }

        It 'returns Status Fail (an unlinked GPO does not enforce anything)' {
            $f = Test-SMBSigning
            $f.Status                       | Should -Be 'Fail'
            $f.Evidence.ServerSideCovered   | Should -BeFalse
            $f.Evidence.ClientSideCovered   | Should -BeFalse
        }
    }
}
