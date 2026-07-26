@{
    RootModule           = 'Invoke-ADHardening.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'b7c2f5a8-1d3e-4a9c-9b6f-2e5d8f7c1a4b'
    Author               = 'Invoke-ADHardening contributors'
    CompanyName          = 'Community'
    Copyright            = '(c) 2026 Invoke-ADHardening contributors. Released under the GNU AGPLv3.'
    Description          = 'Audits Active Directory for the 10 most common misconfigurations found on internal pentests, and optionally remediates them.'
    PowerShellVersion    = '5.1'
    RequiredModules      = @('ActiveDirectory','GroupPolicy')
    FunctionsToExport    = @('Invoke-ADHardening')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData = @{
        PSData = @{
            Tags         = @('ActiveDirectory','Security','Hardening','Audit','GPO')
            ProjectUri   = 'https://github.com/HenryHuevo/Invoke-ADHardening'
            LicenseUri   = 'https://github.com/HenryHuevo/Invoke-ADHardening/blob/main/LICENSE'
            ReleaseNotes = 'Initial public release: 10 audit checks (ADH-001..ADH-010), 7 opt-in auto-fixes, implement phase with -WhatIf preview and per-fix verification.'
        }
    }
}
