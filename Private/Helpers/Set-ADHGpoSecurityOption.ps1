function Merge-ADHGptTmplSection {
    <#
    .SYNOPSIS
        Merges a set of "key = value" lines into one named section of a GPO's
        security template (GptTmpl.inf under SYSVOL), preserving every other
        section verbatim.
    .DESCRIPTION
        Shared core for the Security-Option ([Registry Values]) and account-policy
        ([System Access]) writers. It:

          1. Ensures the SecEdit directory + the mandatory [Unicode]/[Version]
             scaffolding exist.
          2. Parses the INF into ordered sections, replacing any existing line
             whose key (text before the first '=') matches one we're writing,
             and appending the rest.
          3. Writes the file back as UTF-16 LE (the encoding secedit requires).

        Version bumping and CSE registration are the caller's next step via
        Update-ADHGpoMachineVersion - this function only rewrites the INF.
    .PARAMETER GpoId
        GUID of the target GPO.
    .PARAMETER SectionName
        INF section to merge into, e.g. 'Registry Values' or 'System Access'.
    .PARAMETER Entry
        One or more hashtables, each @{ Key=<text before '='>; Line=<full line> }.
    .OUTPUTS
        [string] full path to the GptTmpl.inf that was written.
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal INF-writer; the Set-* fix that ultimately calls this owns the ShouldProcess/confirmation gate.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][string]$SectionName,
        [Parameter(Mandatory)][hashtable[]]$Entry
    )

    $domain     = Get-ADDomain -ErrorAction Stop
    $gpoFolder  = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$($GpoId.ToString().ToUpperInvariant())}"
    $secEditDir = Join-Path $gpoFolder 'Machine\Microsoft\Windows NT\SecEdit'
    $infPath    = Join-Path $secEditDir 'GptTmpl.inf'

    if (-not (Test-Path $secEditDir)) {
        New-Item -Path $secEditDir -ItemType Directory -Force | Out-Null
    }

    # Parse the INF into ordered sections, preserving everything we don't touch
    # (Default policies ship [System Access]/[Privilege Rights]/etc.).
    $sections = [ordered]@{}
    $order    = New-Object System.Collections.Generic.List[string]
    $current  = $null
    if (Test-Path $infPath) {
        foreach ($line in (Get-Content -LiteralPath $infPath)) {
            if ($line -match '^\s*\[(.+?)\]\s*$') {
                $current = $Matches[1]
                if (-not $sections.Contains($current)) {
                    $sections[$current] = New-Object System.Collections.Generic.List[string]
                    $order.Add($current)
                }
            } elseif ($null -ne $current) {
                $sections[$current].Add($line)
            }
        }
    }

    function Initialize-Section($name) {
        if (-not $sections.Contains($name)) {
            $sections[$name] = New-Object System.Collections.Generic.List[string]
            $order.Add($name)
        }
    }

    Initialize-Section 'Unicode'
    if (-not ($sections['Unicode'] | Where-Object { $_ -match '^\s*Unicode\s*=' })) {
        $sections['Unicode'].Add('Unicode=yes')
    }
    Initialize-Section 'Version'
    if (-not ($sections['Version'] | Where-Object { $_ -match '^\s*signature\s*=' })) {
        $sections['Version'].Add('signature="$CHICAGO$"')
    }
    if (-not ($sections['Version'] | Where-Object { $_ -match '^\s*Revision\s*=' })) {
        $sections['Version'].Add('Revision=1')
    }
    Initialize-Section $SectionName

    $sec = $sections[$SectionName]
    foreach ($e in $Entry) {
        $key  = [string]$e.Key
        $line = [string]$e.Line
        $idx = -1
        for ($i = 0; $i -lt $sec.Count; $i++) {
            $existingKey = ($sec[$i] -split '=', 2)[0]
            if ($existingKey.Trim() -ieq $key.Trim()) { $idx = $i; break }
        }
        if ($idx -ge 0) { $sec[$idx] = $line } else { $sec.Add($line) }
    }

    # Reconstruct the file.
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($s in $order) {
        $out.Add("[$s]")
        foreach ($l in $sections[$s]) { $out.Add($l) }
    }
    # GptTmpl.inf must be Unicode (UTF-16 LE with BOM).
    [System.IO.File]::WriteAllLines($infPath, $out, [System.Text.Encoding]::Unicode)

    return $infPath
}

function Update-ADHGpoMachineVersion {
    <#
    .SYNOPSIS
        Bumps a GPO's computer version (GPT.ini + AD versionNumber) and registers
        the Security client-side-extension after a GptTmpl.inf change.
    .DESCRIPTION
        Called after Merge-ADHGptTmplSection rewrites the security template. It:

          1. Increments the computer version in BOTH GPT.ini (SYSVOL) and the
             versionNumber attribute on the GPO's AD object, keeping them in sync
             (a mismatch silently stops clients re-applying the policy).
          2. Registers the Security CSE GUID in gPCMachineExtensionNames (merging,
             never clobbering, any CSE the GPO already declares - e.g. the Registry
             CSE an Administrative Template in the same GPO depends on).
    .PARAMETER GpoId
        GUID of the GPO.
    .OUTPUTS
        [int] the new computer version number.
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal version/CSE plumbing; the Set-* fix that ultimately calls this owns the ShouldProcess/confirmation gate.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$GpoId
    )

    # Security CSE (Security Settings) + its SecEdit snap-in tool extension.
    # Required in gPCMachineExtensionNames for the DC/clients to process the
    # security template (both [Registry Values] Security Options AND [System
    # Access] account policy are handled by this same CSE).
    $securityCse  = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
    $securityTool = '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'

    $domain     = Get-ADDomain -ErrorAction Stop
    $gpoFolder  = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$($GpoId.ToString().ToUpperInvariant())}"
    $gptIniPath = Join-Path $gpoFolder 'GPT.ini'
    $gpoAdDn    = "CN={$($GpoId.ToString().ToUpperInvariant())},CN=Policies,CN=System,$($domain.DistinguishedName)"

    # The version is a 32-bit value: high word = user version, low word =
    # computer version. Incrementing by 1 bumps the computer version, which is
    # what a security-template (machine) change requires.
    $currentVersion = 0
    if (Test-Path $gptIniPath) {
        foreach ($line in (Get-Content -LiteralPath $gptIniPath)) {
            if ($line -match '^\s*Version\s*=\s*(\d+)\s*$') { $currentVersion = [int]$Matches[1]; break }
        }
    }
    $newVersion = $currentVersion + 1

    if (Test-Path $gptIniPath) {
        $gptLines = Get-Content -LiteralPath $gptIniPath
        if ($gptLines | Where-Object { $_ -match '^\s*Version\s*=' }) {
            $gptLines = $gptLines | ForEach-Object {
                if ($_ -match '^\s*Version\s*=') { "Version=$newVersion" } else { $_ }
            }
        } else {
            $gptLines += "Version=$newVersion"
        }
        Set-Content -LiteralPath $gptIniPath -Value $gptLines -Encoding Ascii
    } else {
        Set-Content -LiteralPath $gptIniPath -Value @('[General]', "Version=$newVersion") -Encoding Ascii
    }

    Set-ADObject -Identity $gpoAdDn -Replace @{ versionNumber = $newVersion } -ErrorAction Stop

    $existingCse = (Get-ADObject -Identity $gpoAdDn -Properties gPCMachineExtensionNames -ErrorAction Stop).gPCMachineExtensionNames
    $newCse = Merge-ADHCseGuid -Existing $existingCse -CseGuid $securityCse -ToolGuid $securityTool
    if ($newCse -ne $existingCse) {
        Set-ADObject -Identity $gpoAdDn -Replace @{ gPCMachineExtensionNames = $newCse } -ErrorAction Stop
    }

    return $newVersion
}

function Set-ADHGpoSecurityOption {
    <#
    .SYNOPSIS
        Writes one or more Security Options into a GPO as the real named policy
        (Computer Configuration > Windows Settings > Security Settings > Local
        Policies > Security Options), not as a registry.pol "Extra Registry
        Setting".
    .DESCRIPTION
        The in-box GroupPolicy module has no cmdlet for Security Options. They
        live in the GPO's security template, GptTmpl.inf, under SYSVOL - the
        exact file the GPMC editor writes when you click a Security Option. This
        helper does what the GUI does for you: merges each setting into the
        [Registry Values] section as  <KeyName>=<type>,<value>  (type 4 =
        REG_DWORD) via Merge-ADHGptTmplSection, then bumps the version and
        registers the Security CSE via Update-ADHGpoMachineVersion.

        The result is identical to navigating the Security Option in GPMC and
        clicking it: the setting shows as the named policy, and
        Get-GPOReport/Get-ADHGpoSettingForOu surface it as a <SecurityOptions>
        node (SettingNumber), not an Extra Registry Setting.

        No external tooling (LGPO.exe etc.) is required; this is RSAT-only.
    .PARAMETER GpoId
        GUID of the target GPO (already created by the caller via New-GPO).
    .PARAMETER Setting
        One or more hashtables, each: @{ KeyName='MACHINE\...\ValueName';
        Type=<int reg type, 4=DWORD>; Value=<int> }. KeyName is the full
        Security-Option key path including the leaf value name, exactly as it
        appears in GptTmpl.inf and Get-GPOReport (MACHINE\..., not HKLM\...).
    .OUTPUTS
        PSCustomObject: GpoId, GptTmplPath, NewVersion, Settings (the merged
        KeyName=type,value strings).
    .NOTES
        Caller is responsible for ShouldProcess / confirmation gating; this
        helper performs the mutation unconditionally when invoked. It is NOT in
        the read-only audit path.
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Caller (the Set-* fix) owns the ShouldProcess/confirmation gate; this internal helper performs the already-approved mutation. Adding ShouldProcess here would double-prompt.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][hashtable[]]$Setting
    )

    $mergedLines = @()
    $entries     = @()
    foreach ($s in $Setting) {
        $key  = $s.KeyName
        $type = [int]$s.Type
        $val  = [int]$s.Value
        $entry = "$key=$type,$val"
        $mergedLines += $entry
        $entries     += @{ Key = $key; Line = $entry }
    }

    $infPath    = Merge-ADHGptTmplSection -GpoId $GpoId -SectionName 'Registry Values' -Entry $entries
    $newVersion = Update-ADHGpoMachineVersion -GpoId $GpoId

    return [PSCustomObject]@{
        GpoId       = $GpoId
        GptTmplPath = $infPath
        NewVersion  = $newVersion
        Settings    = $mergedLines
    }
}

function Set-ADHGpoSystemAccess {
    <#
    .SYNOPSIS
        Writes account-policy settings (password + lockout policy) into a GPO's
        [System Access] section as the real named policies (Computer
        Configuration > Windows Settings > Security Settings > Account Policies),
        not as registry.pol "Extra Registry Settings".
    .DESCRIPTION
        Account policy (Password Policy + Account Lockout Policy) lives in the
        [System Access] section of GptTmpl.inf - a different section from the
        Security Options that Set-ADHGpoSecurityOption writes, but the same file
        and the same Security CSE. This helper merges the named values via
        Merge-ADHGptTmplSection, then bumps the version + registers the CSE via
        Update-ADHGpoMachineVersion.

        IMPORTANT: domain account policy only takes effect when the GPO is linked
        at the DOMAIN ROOT (account policy in an OU-linked GPO sets the *local*
        SAM of member machines, not domain accounts). The caller is responsible
        for that link (and, where it must beat the Default Domain Policy, for
        marking the link Enforced).

        Value encoding follows the security-template convention, NOT the
        Set-ADDefaultDomainPasswordPolicy / GUI convention. Notably:
          MaximumPasswordAge = -1   means "passwords never expire" (GUI 0 days).
          LockoutDuration / ResetLockoutCount are in MINUTES.
          PasswordComplexity = 1    enables complexity.
    .PARAMETER GpoId
        GUID of the target GPO (already created by the caller via New-GPO).
    .PARAMETER Setting
        Hashtable of [System Access] name -> integer value, e.g.
        @{ MinimumPasswordLength = 15; PasswordComplexity = 1;
           MaximumPasswordAge = -1; LockoutBadCount = 5;
           LockoutDuration = 15; ResetLockoutCount = 15 }.
    .OUTPUTS
        PSCustomObject: GpoId, GptTmplPath, NewVersion, Settings (the merged
        "Name = value" strings).
    .NOTES
        Caller owns ShouldProcess / confirmation gating; NOT in the read-only
        audit path.
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Caller (the Set-* fix) owns the ShouldProcess/confirmation gate; this internal helper performs the already-approved mutation.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][hashtable]$Setting
    )

    $mergedLines = @()
    $entries     = @()
    foreach ($name in $Setting.Keys) {
        $val  = [int]$Setting[$name]
        $line = "$name = $val"
        $mergedLines += $line
        $entries     += @{ Key = $name; Line = $line }
    }

    $infPath    = Merge-ADHGptTmplSection -GpoId $GpoId -SectionName 'System Access' -Entry $entries
    $newVersion = Update-ADHGpoMachineVersion -GpoId $GpoId

    return [PSCustomObject]@{
        GpoId       = $GpoId
        GptTmplPath = $infPath
        NewVersion  = $newVersion
        Settings    = $mergedLines
    }
}

function Get-ADHGpoSecurityOption {
    <#
    .SYNOPSIS
        Reads a single Security Option's value from a GPO's GptTmpl.inf.
    .DESCRIPTION
        Companion reader for Set-ADHGpoSecurityOption, used by the fixes to
        capture before/after state. Returns the integer value the GPO defines
        for the given Security-Option key, or $null if the GPO does not set it
        (no GptTmpl.inf, or no matching [Registry Values] line).
    .PARAMETER GpoId
        GUID of the GPO.
    .PARAMETER KeyName
        Full Security-Option key path, e.g.
        'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'.
    .OUTPUTS
        [int] or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][string]$KeyName
    )

    $domain  = Get-ADDomain -ErrorAction Stop
    $infPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$($GpoId.ToString().ToUpperInvariant())}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    if (-not (Test-Path $infPath)) { return $null }

    $inRegValues = $false
    foreach ($line in (Get-Content -LiteralPath $infPath)) {
        if ($line -match '^\s*\[(.+?)\]\s*$') {
            $inRegValues = ($Matches[1] -ieq 'Registry Values')
            continue
        }
        if (-not $inRegValues) { continue }
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2 -and $parts[0].Trim() -ieq $KeyName) {
            # value is "<type>,<value>"
            $valToken = ($parts[1] -split ',')[-1]
            $parsed = 0
            if ([int]::TryParse($valToken.Trim(), [ref]$parsed)) { return $parsed }
            return $null
        }
    }
    return $null
}

function Get-ADHGpoSystemAccess {
    <#
    .SYNOPSIS
        Reads a single [System Access] account-policy value from a GPO's
        GptTmpl.inf.
    .DESCRIPTION
        Companion reader for Set-ADHGpoSystemAccess, used by the ADH-009 fix to
        capture before/after state. Returns the integer value the GPO defines for
        the given account-policy name, or $null if the GPO does not set it.
    .PARAMETER GpoId
        GUID of the GPO.
    .PARAMETER Name
        Account-policy value name, e.g. 'MinimumPasswordLength',
        'MaximumPasswordAge', 'LockoutBadCount'.
    .OUTPUTS
        [int] or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][string]$Name
    )

    $domain  = Get-ADDomain -ErrorAction Stop
    $infPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$($GpoId.ToString().ToUpperInvariant())}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    if (-not (Test-Path $infPath)) { return $null }

    $inSystemAccess = $false
    foreach ($line in (Get-Content -LiteralPath $infPath)) {
        if ($line -match '^\s*\[(.+?)\]\s*$') {
            $inSystemAccess = ($Matches[1] -ieq 'System Access')
            continue
        }
        if (-not $inSystemAccess) { continue }
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2 -and $parts[0].Trim() -ieq $Name) {
            $parsed = 0
            if ([int]::TryParse($parts[1].Trim(), [ref]$parsed)) { return $parsed }
            return $null
        }
    }
    return $null
}

function Merge-ADHCseGuid {
    <#
    .SYNOPSIS
        Merges a client-side-extension GUID pair into a gPCMachineExtensionNames
        string, preserving any CSEs already present and keeping the canonical
        sorted [{CSE}{Tool}...] ordering.
    .DESCRIPTION
        gPCMachineExtensionNames groups GUIDs as [{CSE-GUID}{Tool-GUID}...],
        sorted ascending by GUID, both between groups (by CSE) and within a
        group (the tool GUIDs). This merge is idempotent and never drops an
        existing CSE - important because an Administrative Template
        (Set-GPRegistryValue, Registry CSE) and a Security Option (this helper,
        Security CSE) can coexist in the same GPO.
    #>
    [CmdletBinding()]
    param(
        [string]$Existing,
        [Parameter(Mandatory)][string]$CseGuid,
        [Parameter(Mandatory)][string]$ToolGuid
    )

    $cse  = '{' + $CseGuid.Trim('{}').ToUpperInvariant()  + '}'
    $tool = '{' + $ToolGuid.Trim('{}').ToUpperInvariant() + '}'

    $map = [ordered]@{}
    if ($Existing) {
        foreach ($group in [regex]::Matches($Existing, '\[(.*?)\]')) {
            $guids = @([regex]::Matches($group.Groups[1].Value, '\{[0-9A-Fa-f\-]+\}') |
                ForEach-Object { $_.Value.ToUpperInvariant() })
            if ($guids.Count -lt 1) { continue }
            $key = $guids[0]
            if (-not $map.Contains($key)) { $map[$key] = New-Object System.Collections.Generic.List[string] }
            foreach ($t in @($guids | Select-Object -Skip 1)) {
                if (-not $map[$key].Contains($t)) { $map[$key].Add($t) }
            }
        }
    }
    if (-not $map.Contains($cse)) { $map[$cse] = New-Object System.Collections.Generic.List[string] }
    if (-not $map[$cse].Contains($tool)) { $map[$cse].Add($tool) }

    $sb = ''
    foreach ($key in ($map.Keys | Sort-Object)) {
        $toolsSorted = @($map[$key] | Sort-Object)
        $sb += '[' + $key + ($toolsSorted -join '') + ']'
    }
    return $sb
}
