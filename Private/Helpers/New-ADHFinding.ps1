function New-ADHFinding {
    <#
    .SYNOPSIS
        Factory for the standardized Invoke-ADHardening finding object.
    .DESCRIPTION
        Every Test-* check returns one of these. Locking the shape down here
        means downstream consumers (report renderers, implement phase, JSON
        sinks) can rely on a stable schema.
    .EXAMPLE
        New-ADHFinding -CheckId ADH-001 -CheckName 'LLMNR Disabled' `
            -Category 'Legacy Protocols' -Severity High -Status Fail `
            -Description 'No GPO disables LLMNR.'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$CheckName,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [Parameter(Mandatory)]
        [ValidateSet('Pass','Fail','Warning','Error','NotApplicable')]
        [string]$Status,
        [Parameter(Mandatory)][string]$Description,
        [hashtable]$Evidence = @{},
        [string[]]$AffectedObjects = @(),
        [string]$RemediationSteps = '',
        [bool]$AutoFixAvailable = $false,
        [string]$FixFunction = '',
        [string[]]$References = @()
    )

    [PSCustomObject]@{
        CheckId          = $CheckId
        CheckName        = $CheckName
        Category         = $Category
        Severity         = $Severity
        Status           = $Status
        Description      = $Description
        Evidence         = $Evidence
        AffectedObjects  = $AffectedObjects
        RemediationSteps = $RemediationSteps
        AutoFixAvailable = $AutoFixAvailable
        FixFunction      = $FixFunction
        References       = $References
        Timestamp        = [DateTime]::UtcNow
    }
}
