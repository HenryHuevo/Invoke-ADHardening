function Test-PreWin2000Group {
    <#
    .SYNOPSIS
        ADH-006 - Inspects the 'Pre-Windows 2000 Compatible Access' group.
    .DESCRIPTION
        This group was created for NT4 RAS compatibility and grants its
        members anonymous-style read access to several AD objects. The
        problematic well-known SIDs to look for:

          S-1-5-7   Anonymous Logon          - always a Fail if present
          S-1-1-0   Everyone                 - always a Fail if present
          S-1-5-11  Authenticated Users      - frequently legitimate (legacy
                                               apps); flag as Warning not Fail

        Severity is Medium per the build spec - higher-impact relay-path
        items (LDAP signing, SMB signing) carry the actual Critical/High
        rating. This check is about reducing pre-auth enumeration surface.
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-006 Pre-Windows 2000 Group - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-006'
        CheckName  = 'Pre-Windows 2000 Compatible Access cleaned'
        Category   = 'Legacy Configuration'
        Severity   = 'Medium'
        References = @(
            'https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers',
            'https://www.thehacker.recipes/ad/movement/builtin-groups#pre-windows-2000-compatible-access',
            'MITRE ATT&CK T1087.002'
        )
    }

    $evidence = @{
        AuditMethod        = 'AD group membership read'
        RequiresElevation  = $false
        Limitations        = ''
        GroupMembers       = @()
        ProblematicMembers = @()
    }

    # SAM name varies by language; use SID for the group lookup.
    $preWin2kSid = 'S-1-5-32-554'
    $bannedSids = @{
        'S-1-5-7'  = 'Anonymous Logon'
        'S-1-1-0'  = 'Everyone'
        'S-1-5-11' = 'Authenticated Users'
    }

    try {
        $group = Get-ADGroup -Identity $preWin2kSid -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $group -ErrorAction Stop

        $evidence.GroupMembers = @($members | ForEach-Object {
            [PSCustomObject]@{
                Name           = $_.Name
                SamAccountName = $_.SamAccountName
                SID            = $_.SID.Value
                ObjectClass    = $_.objectClass
            }
        })

        $problematic = @($members | Where-Object { $bannedSids.ContainsKey($_.SID.Value) } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    SID  = $_.SID.Value
                    WellKnownName = $bannedSids[$_.SID.Value]
                }
            })
        $evidence.ProblematicMembers = $problematic

        $hardFail = @($problematic | Where-Object { $_.SID -in @('S-1-5-7','S-1-1-0') })
        $authUsersPresent = [bool]($problematic | Where-Object { $_.SID -eq 'S-1-5-11' })

        if ($hardFail.Count -gt 0) {
            $names = ($hardFail | ForEach-Object WellKnownName) -join ', '
            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "Pre-Windows 2000 Compatible Access contains: $names. This permits anonymous-style enumeration of sensitive AD attributes." `
                -Evidence $evidence `
                -AffectedObjects $hardFail.SID `
                -RemediationSteps "Remove Anonymous Logon (S-1-5-7) and Everyone (S-1-1-0) from the Pre-Windows 2000 Compatible Access group. Run: Invoke-ADHardening -Mode Implement -IncludeCheckIds ADH-006. (Authenticated Users membership, if present, is NOT removed automatically - that often breaks legacy apps.)" `
                -AutoFixAvailable $true `
                -FixFunction 'Set-PreWin2000GroupCleaned'

            Write-ADHLog -Level FAIL -Message "ADH-006 Pre-Windows 2000 Group - FAIL ($names)" -Console
        }
        elseif ($authUsersPresent) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Warning' `
                -Description 'Pre-Windows 2000 Compatible Access contains Authenticated Users. This is often legitimate (legacy apps) but expands the pre-auth read surface. Review whether any consumer still depends on it before removing.' `
                -Evidence $evidence `
                -AffectedObjects @('S-1-5-11') `
                -RemediationSteps 'Manual review only. The auto-fix does NOT remove Authenticated Users because it breaks line-of-business compatibility frequently. Audit dependencies first (older Citrix, certain SCCM versions, legacy file servers) then remove via ADUC.' `
                -AutoFixAvailable $false

            Write-ADHLog -Level WARN -Message 'ADH-006 Pre-Windows 2000 Group - WARN (Authenticated Users present; manual review)' -Console
        }
        else {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description "Pre-Windows 2000 Compatible Access contains $($members.Count) member(s), none of which are Anonymous Logon, Everyone, or Authenticated Users." `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-006 Pre-Windows 2000 Group - PASS' -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-006 Pre-Windows 2000 Group - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
