#requires -Modules Pester

# Exercises Invoke-ADHImplementPhase against a fixture audit. The Set-* fixes
# and Test-* checks are stubbed and mocked so no AD/GPO state is touched; we
# assert which fixes are invoked, the A/S/R/Q loop, and -Force/-WhatIf gating.

BeforeAll {
    $script:repoRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:fixtureDir = Join-Path $PSScriptRoot 'Fixtures'

    . (Join-Path $repoRoot 'Tests/TestStubs.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHFinding.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/Get-ADHReportAssets.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/New-ADHImplementationReport.ps1')
    . (Join-Path $repoRoot 'Private/Helpers/Invoke-ADHImplementPhase.ps1')

    # Fix + check stubs the implement phase dispatches to by name.
    function Set-LLMNRDisabled {
        [CmdletBinding(SupportsShouldProcess)] param()
        [pscustomobject]@{ Success = $true; ErrorMessage = $null; BeforeState = @{}; AfterState = @{} }
    }
    function Set-SMBSigningRequired {
        [CmdletBinding(SupportsShouldProcess)] param()
        [pscustomobject]@{ Success = $true; ErrorMessage = $null; BeforeState = @{}; AfterState = @{} }
    }
    function Test-LLMNR {
        [CmdletBinding()] param()
        New-ADHFinding -CheckId ADH-001 -CheckName 'LLMNR Disabled' -Category 'Legacy Protocols' `
            -Severity High -Status Pass -Description 'verified'
    }
    function Test-SMBSigning {
        [CmdletBinding()] param()
        New-ADHFinding -CheckId ADH-003 -CheckName 'SMB Signing Required' -Category 'Relay Defenses' `
            -Severity High -Status Pass -Description 'verified'
    }

    $script:fullRegistry = @(
        @{ Id = 'ADH-001'; Test = 'Test-LLMNR';        Fix = 'Set-LLMNRDisabled' }
        @{ Id = 'ADH-003'; Test = 'Test-SMBSigning';   Fix = 'Set-SMBSigningRequired' }
        @{ Id = 'ADH-005'; Test = 'Test-IPv6Mitm6';    Fix = $null }
        @{ Id = 'ADH-007'; Test = 'Test-Kerberoasting'; Fix = $null }
    )

    function New-TempOut {
        $p = Join-Path ([System.IO.Path]::GetTempPath()) ("adh-impl-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        $p
    }
}

Describe 'Invoke-ADHImplementPhase' {

    It 'applies every applicable fix unattended with -Force -Confirm:$false' {
        Mock Set-LLMNRDisabled      { [pscustomobject]@{ Success = $true } }
        Mock Set-SMBSigningRequired { [pscustomobject]@{ Success = $true } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.test' } }

        $out = New-TempOut
        $res = Invoke-ADHImplementPhase -Checks $fullRegistry -ReportPath $fixtureDir `
            -OutputPath $out -Force -Confirm:$false

        Should -Invoke Set-LLMNRDisabled      -Exactly -Times 1
        Should -Invoke Set-SMBSigningRequired -Exactly -Times 1
        ($res | Where-Object CheckId -eq 'ADH-001').Action | Should -Be 'Applied'
        ($res | Where-Object CheckId -eq 'ADH-003').Action | Should -Be 'Applied'
        Test-Path (Join-Path $out 'implementation-report.html')  | Should -BeTrue
        Test-Path (Join-Path $out 'implementation-summary.json') | Should -BeTrue
    }

    It 'invokes fixes in -WhatIf mode when -Force is omitted' {
        Mock Set-LLMNRDisabled      { [pscustomobject]@{ Success = $true } }
        Mock Set-SMBSigningRequired { [pscustomobject]@{ Success = $true } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.test' } }

        $out = New-TempOut
        $res = Invoke-ADHImplementPhase -Checks $fullRegistry -ReportPath $fixtureDir `
            -OutputPath $out -Confirm:$false

        Should -Invoke Set-LLMNRDisabled -Exactly -Times 1 -ParameterFilter { $WhatIf -eq $true }
        ($res | Where-Object CheckId -eq 'ADH-001').Action | Should -Be 'WhatIf'
    }

    It 'previews, then one-by-one honours [A]pply then Skip [R]est' {
        Mock Set-LLMNRDisabled      { [pscustomobject]@{ Success = $true } }
        Mock Set-SMBSigningRequired { [pscustomobject]@{ Success = $true } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.test' } }
        # y = apply, O = one-by-one, A = apply ADH-001, R = skip the rest.
        $script:rhQueue = [System.Collections.Queue]::new()
        'y','O','A','R' | ForEach-Object { $script:rhQueue.Enqueue($_) }
        Mock Read-Host { $script:rhQueue.Dequeue() }

        $out = New-TempOut
        $res = Invoke-ADHImplementPhase -Checks $fullRegistry -ReportPath $fixtureDir `
            -OutputPath $out

        # Each fix is previewed once under -WhatIf; only ADH-001 is applied for real.
        Should -Invoke Set-LLMNRDisabled      -Exactly -Times 1 -ParameterFilter { $WhatIf -ne $true }
        Should -Invoke Set-SMBSigningRequired -Exactly -Times 0 -ParameterFilter { $WhatIf -ne $true }
        ($res | Where-Object CheckId -eq 'ADH-001').Action | Should -Be 'Applied'
        ($res | Where-Object CheckId -eq 'ADH-003').Action | Should -Be 'Skipped'
        # R still produces a report.
        Test-Path (Join-Path $out 'implementation-report.html') | Should -BeTrue
    }

    It 'applies all at once when the operator answers [A]ll' {
        Mock Set-LLMNRDisabled      { [pscustomobject]@{ Success = $true } }
        Mock Set-SMBSigningRequired { [pscustomobject]@{ Success = $true } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.test' } }
        # y = apply, A = all at once (no per-finding prompts).
        $script:rhQueue = [System.Collections.Queue]::new()
        'y','A' | ForEach-Object { $script:rhQueue.Enqueue($_) }
        Mock Read-Host { $script:rhQueue.Dequeue() }

        $out = New-TempOut
        $res = Invoke-ADHImplementPhase -Checks $fullRegistry -ReportPath $fixtureDir `
            -OutputPath $out

        Should -Invoke Set-LLMNRDisabled      -Exactly -Times 1 -ParameterFilter { $WhatIf -ne $true }
        Should -Invoke Set-SMBSigningRequired -Exactly -Times 1 -ParameterFilter { $WhatIf -ne $true }
        ($res | Where-Object CheckId -eq 'ADH-001').Action | Should -Be 'Applied'
        ($res | Where-Object CheckId -eq 'ADH-003').Action | Should -Be 'Applied'
    }

    It 'previews only and applies nothing when the operator declines (N)' {
        Mock Set-LLMNRDisabled      { [pscustomobject]@{ Success = $true } }
        Mock Set-SMBSigningRequired { [pscustomobject]@{ Success = $true } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.test' } }
        Mock Read-Host { 'n' }

        $out = New-TempOut
        $res = Invoke-ADHImplementPhase -Checks $fullRegistry -ReportPath $fixtureDir `
            -OutputPath $out

        # Previewed under -WhatIf, but nothing applied for real.
        Should -Invoke Set-LLMNRDisabled      -Exactly -Times 0 -ParameterFilter { $WhatIf -ne $true }
        Should -Invoke Set-SMBSigningRequired -Exactly -Times 0 -ParameterFilter { $WhatIf -ne $true }
        ($res | Where-Object CheckId -eq 'ADH-001').Action | Should -Be 'WhatIf'
        # Decline still leaves a dry-run report behind.
        Test-Path (Join-Path $out 'implementation-report.html') | Should -BeTrue
    }

    It 'writes no report when the operator [Q]uits one-by-one' {
        Mock Set-LLMNRDisabled      { [pscustomobject]@{ Success = $true } }
        Mock Set-SMBSigningRequired { [pscustomobject]@{ Success = $true } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.test' } }
        # y = apply, O = one-by-one, Q = quit at the first finding.
        $script:rhQueue = [System.Collections.Queue]::new()
        'y','O','Q' | ForEach-Object { $script:rhQueue.Enqueue($_) }
        Mock Read-Host { $script:rhQueue.Dequeue() }

        $out = New-TempOut
        $null = Invoke-ADHImplementPhase -Checks $fullRegistry -ReportPath $fixtureDir `
            -OutputPath $out

        Should -Invoke Set-LLMNRDisabled -Exactly -Times 0 -ParameterFilter { $WhatIf -ne $true }
        Test-Path (Join-Path $out 'implementation-report.html') | Should -BeFalse
    }

    It 'returns cleanly when no findings are in scope' {
        Mock Set-LLMNRDisabled { [pscustomobject]@{ Success = $true } }
        $out = New-TempOut
        # Only ADH-007 (a Pass, no fix) in scope -> nothing applicable.
        $scoped = $fullRegistry | Where-Object { $_.Id -eq 'ADH-007' }

        $res = Invoke-ADHImplementPhase -Checks $scoped -ReportPath $fixtureDir `
            -OutputPath $out -Force -Confirm:$false

        Should -Invoke Set-LLMNRDisabled -Exactly -Times 0
        Test-Path (Join-Path $out 'implementation-report.html') | Should -BeFalse
    }

    It 'marks a finding Failed when its fix function is missing' {
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.test' } }
        $reg = @( @{ Id = 'ADH-001'; Test = 'Test-LLMNR'; Fix = 'Set-DoesNotExist' } )

        $out = New-TempOut
        $res = Invoke-ADHImplementPhase -Checks $reg -ReportPath $fixtureDir `
            -OutputPath $out -Force -Confirm:$false

        $r = $res | Where-Object CheckId -eq 'ADH-001'
        $r.Action | Should -Be 'Failed'
        $r.Notes  | Should -Match 'not found'
    }
}
