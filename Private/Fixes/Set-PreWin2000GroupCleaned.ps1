function Set-PreWin2000GroupCleaned {
    <#
    .SYNOPSIS
        ADH-006 fix - removes Anonymous Logon (and optionally Everyone)
        from Pre-Windows 2000 Compatible Access.
    .DESCRIPTION
        Deliberately conservative. We remove only:
          S-1-5-7   Anonymous Logon  - never legitimate
          S-1-1-0   Everyone         - never legitimate

        We DO NOT remove:
          S-1-5-11  Authenticated Users - frequently legitimate (legacy apps);
                                          operator must remove manually after
                                          dependency review.

        Captures before/after group membership snapshot to changes.jsonl.
    .PARAMETER WhatIfPause
        Internal - set by the implement-phase orchestrator. Ignored otherwise.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param()

    $changeRecord = [PSCustomObject]@{
        CheckId      = 'ADH-006'
        FixFunction  = 'Set-PreWin2000GroupCleaned'
        Timestamp    = [DateTime]::UtcNow
        BeforeState  = $null
        AfterState   = $null
        Success      = $false
        ErrorMessage = $null
    }

    $preWin2kSid = 'S-1-5-32-554'
    $sidsToRemove = @{
        'S-1-5-7' = 'Anonymous Logon'
        'S-1-1-0' = 'Everyone'
    }

    try {
        $group = Get-ADGroup -Identity $preWin2kSid -ErrorAction Stop
        $beforeMembers = @(Get-ADGroupMember -Identity $group -ErrorAction Stop |
            ForEach-Object { @{ Name = $_.Name; SID = $_.SID.Value } })

        $changeRecord.BeforeState = @{
            GroupDN     = $group.DistinguishedName
            MemberCount = $beforeMembers.Count
            Members     = $beforeMembers
        }

        $toRemove = @($beforeMembers | Where-Object { $sidsToRemove.ContainsKey($_.SID) })
        if ($toRemove.Count -eq 0) {
            Write-ADHLog -Level INFO -Message 'ADH-006 fix skipped: no banned SIDs present' -Console
            $changeRecord.AfterState = $changeRecord.BeforeState
            $changeRecord.Success = $true
            return $changeRecord
        }

        $names = ($toRemove | ForEach-Object { $sidsToRemove[$_.SID] }) -join ', '

        if (-not $PSCmdlet.ShouldProcess(
            "Group '$($group.Name)'",
            "Remove members: $names")) {
            return $changeRecord
        }

        foreach ($m in $toRemove) {
            Write-ADHLog -Level FIX -Message "Removing $($sidsToRemove[$m.SID]) ($($m.SID)) from $($group.Name)" -Console
            # Pass the SID via Get-ADObject -> Remove-ADGroupMember to handle
            # well-known SIDs that may not resolve through normal -Members.
            $principal = Get-ADObject -Filter { objectSid -eq $m.SID } -ErrorAction Stop
            if ($principal) {
                Remove-ADGroupMember -Identity $group -Members $principal -Confirm:$false -ErrorAction Stop
            } else {
                Write-ADHLog -Level WARN -Message "Could not resolve SID $($m.SID) to an AD object - skipping" -Console
            }
        }

        $afterMembers = @(Get-ADGroupMember -Identity $group -ErrorAction Stop |
            ForEach-Object { @{ Name = $_.Name; SID = $_.SID.Value } })

        $changeRecord.AfterState = @{
            GroupDN     = $group.DistinguishedName
            MemberCount = $afterMembers.Count
            Members     = $afterMembers
        }

        $stillPresent = @($afterMembers | Where-Object { $sidsToRemove.ContainsKey($_.SID) })
        $changeRecord.Success = ($stillPresent.Count -eq 0)

        if ($changeRecord.Success) {
            Write-ADHLog -Level FIX -Message "ADH-006 Pre-Windows 2000 Group - FIX applied ($($toRemove.Count) member(s) removed)" -Console
            if ($beforeMembers | Where-Object { $_.SID -eq 'S-1-5-11' }) {
                Write-Host '  NOTE: Authenticated Users is still a member. Auto-fix does not remove it.' -ForegroundColor Yellow
                Write-Host '        Audit dependencies (legacy apps, file servers) and remove via ADUC manually.' -ForegroundColor Yellow
            }
        } else {
            Write-ADHLog -Level ERROR -Message "ADH-006 fix verify failed; banned SIDs still present: $($stillPresent.SID -join ', ')" -Console
        }
    }
    catch {
        $changeRecord.ErrorMessage = $_.Exception.Message
        Write-ADHLog -Level ERROR -Message "ADH-006 fix failed: $($_.Exception.Message)" -Console
        throw
    }
    finally {
        if ($script:ADHLogPath) {
            $changeRecord | ConvertTo-Json -Compress -Depth 10 |
                Add-Content -Path (Join-Path $script:ADHLogPath 'changes.jsonl')
        }
    }

    return $changeRecord
}
