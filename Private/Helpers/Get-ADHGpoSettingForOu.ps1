function Get-ADHGpoSettingForOu {
    <#
    .SYNOPSIS
        Looks up a single registry-shaped GPO setting across every GPO linked
        (or inherited) at a given OU.
    .DESCRIPTION
        AD has two ways to express a settings like "Domain controller: LDAP
        server signing requirements":

          1. Registry policy (registry.pol) - written by 'Computer Configuration
             > Administrative Templates' or by Set-GPRegistryValue. Readable
             with Get-GPRegistryValue.

          2. Security Options (GptTmpl.inf) - written by 'Computer
             Configuration > Windows Settings > Security Settings > Local
             Policies > Security Options'. NOT visible to Get-GPRegistryValue;
             you have to parse Get-GPOReport XML.

        Both paths land the same registry value on the target after gpupdate,
        and Microsoft documents the LDAP signing / channel binding settings
        as Security Options - so the XML path is the typical case.

        This helper tries Path 1 first (cheap) and falls back to Path 2
        (XML report parse). It returns one row per GPO that defines the
        setting; the caller decides what to do with multiple definitions.
    .PARAMETER OuDN
        Distinguished name of the OU. For ADH-004 use
        'OU=Domain Controllers,<domainDN>'.
    .PARAMETER RegistryKey
        Registry policy key, e.g. 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'.
    .PARAMETER ValueName
        Registry value name, e.g. 'LDAPServerIntegrity'.
    .PARAMETER IncludeInherited
        Also consider GPOs linked at ancestor OUs / domain root that get
        inherited at the target OU.
    .OUTPUTS
        Array of PSCustomObject with: GpoName, GpoId, OuDN, Value, Source
        ('RegistryPolicy' | 'SecurityOption'), LinkEnabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OuDN,
        [Parameter(Mandatory)][string]$RegistryKey,
        [Parameter(Mandatory)][string]$ValueName,
        [switch]$IncludeInherited
    )

    # Security Options express the path with MACHINE\... and the value name as
    # part of the key, not separately.
    $secOptKey = ($RegistryKey -replace '^HKLM\\', 'MACHINE\') + "\$ValueName"

    $inherit = Get-GPInheritance -Target $OuDN -ErrorAction Stop
    $links = if ($IncludeInherited) { $inherit.InheritedGpoLinks } else { $inherit.GpoLinks }

    $results = @()
    foreach ($link in $links) {
        if (-not $link.Enabled) { continue }

        $gpo = Get-GPO -Guid $link.GpoId -ErrorAction SilentlyContinue
        if (-not $gpo) { continue }

        # Path 1: Registry policy
        $rp = $null
        try {
            $rp = Get-GPRegistryValue -Guid $gpo.Id -Key $RegistryKey -ValueName $ValueName -ErrorAction Stop
        }
        catch [System.ArgumentException] { }  # value not present in this GPO
        catch { Write-ADHLog -Level DEBUG -Message "Get-GPRegistryValue threw on $($gpo.DisplayName): $($_.Exception.Message)" }

        if ($rp -and $null -ne $rp.Value) {
            $results += [PSCustomObject]@{
                GpoName     = $gpo.DisplayName
                GpoId       = $gpo.Id
                OuDN        = $OuDN
                Value       = $rp.Value
                Source      = 'RegistryPolicy'
                LinkEnabled = $true
            }
            continue
        }

        # Path 2: Security Options via XML report
        try {
            [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
            $nodes = $report.SelectNodes("//*[local-name()='SecurityOptions']")
            foreach ($n in $nodes) {
                $knNode = $n.SelectSingleNode("*[local-name()='KeyName']")
                if (-not $knNode) { continue }
                if ($knNode.InnerText -ieq $secOptKey) {
                    $snNode = $n.SelectSingleNode("*[local-name()='SettingNumber']")
                    if ($snNode -and $snNode.InnerText) {
                        $results += [PSCustomObject]@{
                            GpoName     = $gpo.DisplayName
                            GpoId       = $gpo.Id
                            OuDN        = $OuDN
                            Value       = [int]$snNode.InnerText
                            Source      = 'SecurityOption'
                            LinkEnabled = $true
                        }
                    }
                }
            }
        }
        catch {
            Write-ADHLog -Level DEBUG -Message "Get-GPOReport failed on $($gpo.DisplayName): $($_.Exception.Message)"
        }
    }

    # NB: return the array unrolled (no leading comma). The sole caller wraps
    # every call in @(), so 0/1/many rows all collect correctly. A leading
    # comma here would emit the whole array as a single pipeline item, and the
    # caller's @() would then yield ONE element that is itself the row array -
    # making $row.Value an Object[] and breaking the [int] cast downstream once
    # two or more GPOs define the same value (e.g. after remediation adds a GPO
    # alongside the Default Domain Controllers Policy).
    return $results
}
