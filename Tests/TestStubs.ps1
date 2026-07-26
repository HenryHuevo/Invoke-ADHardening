# Stubs for external cmdlets so Pester's Mock can bind to them on
# machines without RSAT / NetSecurity / Locksmith installed.
#
# Parameters that test files filter on with -ParameterFilter MUST be
# declared by name here — Pester evaluates filter blocks in a scope where
# parameter values are bound to the names from the function signature.
# Other parameters are swallowed by $Rest so callers can pass anything.
#
# Write-ADHLog is stubbed out completely so checks don't try to write to
# $script:ADHLogPath during tests.

function Write-ADHLog {
    [CmdletBinding()]
    param([Parameter(ValueFromRemainingArguments)]$Rest)
}

# --- GroupPolicy module ---

function Get-GPO {
    [CmdletBinding()]
    param([switch]$All, $Name, $Guid, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-GPRegistryValue {
    [CmdletBinding()]
    param($Guid, $Key, $ValueName, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-GPOReport {
    [CmdletBinding()]
    param($Guid, $ReportType, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-GPInheritance {
    [CmdletBinding()]
    param($Target, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function New-GPO       { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Set-GPRegistryValue    { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Remove-GPRegistryValue { [CmdletBinding()]param($Guid, $Key, $ValueName, [Parameter(ValueFromRemainingArguments)]$Rest) }
function New-GPLink    { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Set-GPLink    { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }

# --- ActiveDirectory module ---

function Get-ADDomain                       { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Get-ADForest                       { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Get-ADRootDSE                      { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Get-ADDefaultDomainPasswordPolicy  { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }

function Get-ADObject {
    [CmdletBinding()]
    param($Identity, $Filter, $Properties, $SearchBase,
          [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-ADUser {
    [CmdletBinding()]
    param($Identity, $Filter, $Properties,
          [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-ADComputer {
    [CmdletBinding()]
    param($Identity, $Filter, $Properties,
          [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-ADGroup {
    [CmdletBinding()]
    param($Identity, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-ADGroupMember {
    [CmdletBinding()]
    param($Identity, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-ADDomainController {
    [CmdletBinding()]
    param($Filter, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Set-ADObject                      { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Set-ADDefaultDomainPasswordPolicy { [CmdletBinding()]param([Parameter(ValueFromRemainingArguments)]$Rest) }

# --- Remote ---
# Invoke-Command is a built-in cmdlet (Microsoft.PowerShell.Core) — always
# available. We don't stub it because the function would shadow the real
# cmdlet and Pester's mock-on-stub doesn't bind -ScriptBlock the same way
# the real cmdlet does. Pester mocks the built-in cmdlet directly instead.

# --- NetSecurity (optional in real life, stubbed unconditionally for tests) ---

function Get-NetFirewallRule {
    [CmdletBinding()]
    param($PolicyStore, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Get-NetFirewallPortFilter {
    [CmdletBinding()]
    param($AssociatedNetFirewallRule, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function New-NetFirewallRule {
    [CmdletBinding()]
    param($PolicyStore, $DisplayName, [Parameter(ValueFromRemainingArguments)]$Rest)
}

function Remove-NetFirewallRule {
    [CmdletBinding()]
    param($PolicyStore, $DisplayName, [Parameter(ValueFromRemainingArguments)]$Rest)
}

# --- Locksmith ---

function Invoke-Locksmith { [CmdletBinding()]param($Mode, $OutputPath, [Parameter(ValueFromRemainingArguments)]$Rest) }
