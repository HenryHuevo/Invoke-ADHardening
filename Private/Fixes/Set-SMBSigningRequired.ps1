function Set-SMBSigningRequired {
    <#
    .SYNOPSIS
        ADH-003 fix - requires SMB signing on both server and client sides by
        configuring the named Security Options in the Invoke-ADHardening
        Hardening GPO.
    .DESCRIPTION
        Configures the two real, GUI-navigable Security Options:
          - "Microsoft network server: Digitally sign communications (always)"
          - "Microsoft network client: Digitally sign communications (always)"
        which set, respectively:
          MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature      = 1
          MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature = 1

        These are Security Options (stored in GptTmpl.inf), NOT registry.pol /
        Administrative Templates. We deliberately write them via
        Set-ADHGpoSecurityOption so GPMC shows them as the named policy rather
        than an "Extra Registry Setting" (which is what Set-GPRegistryValue
        would produce). The setting is created in the named GPO (created if
        missing) and optionally linked at the domain root.
    .PARAMETER GpoName
        GPO to create/update. Defaults to 'Invoke-ADHardening Hardening' -
        the same GPO used by other broad-scope hardening fixes.
    .PARAMETER LinkAtDomainRoot
        Also link the GPO at the domain root (if not already linked).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$GpoName = 'Invoke-ADHardening Hardening',
        [switch]$LinkAtDomainRoot
    )

    $changeRecord = [PSCustomObject]@{
        CheckId      = 'ADH-003'
        FixFunction  = 'Set-SMBSigningRequired'
        Timestamp    = [DateTime]::UtcNow
        BeforeState  = $null
        AfterState   = $null
        Success      = $false
        ErrorMessage = $null
    }

    # Security-Option key paths (MACHINE\..., as they appear in GptTmpl.inf).
    $serverSecOpt = 'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature'
    $clientSecOpt = 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature'

    try {
        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        $before = @{ GpoExists = [bool]$existingGpo }
        if ($existingGpo) {
            $before.GpoId        = $existingGpo.Id
            $before.ServerValue  = Get-ADHGpoSecurityOption -GpoId $existingGpo.Id -KeyName $serverSecOpt
            $before.ClientValue  = Get-ADHGpoSecurityOption -GpoId $existingGpo.Id -KeyName $clientSecOpt
        }
        $changeRecord.BeforeState = $before

        if (-not $PSCmdlet.ShouldProcess(
            "Domain GPO '$GpoName'",
            "Set Security Options 'Microsoft network server/client: Digitally sign communications (always)' (require SMB signing)")) {
            return $changeRecord
        }

        if (-not $existingGpo) {
            Write-ADHLog -Level FIX -Message "Creating GPO: $GpoName" -Console
            $gpo = New-GPO -Name $GpoName -Comment 'Created by Invoke-ADHardening - AD hardening settings'
        } else {
            $gpo = $existingGpo
        }

        Write-ADHLog -Level FIX -Message 'Setting Security Options: require SMB signing (server + client)' -Console
        Set-ADHGpoSecurityOption -GpoId $gpo.Id -Setting @(
            @{ KeyName = $serverSecOpt; Type = 4; Value = 1 },
            @{ KeyName = $clientSecOpt; Type = 4; Value = 1 }
        ) | Out-Null

        if ($LinkAtDomainRoot) {
            $domainDn = (Get-ADDomain).DistinguishedName
            $existingLink = Get-GPInheritance -Target $domainDn |
                Select-Object -ExpandProperty GpoLinks |
                Where-Object { $_.GpoId -eq $gpo.Id }

            if (-not $existingLink) {
                Write-ADHLog -Level FIX -Message "Linking GPO at domain root: $domainDn" -Console
                New-GPLink -Guid $gpo.Id -Target $domainDn -LinkEnabled Yes | Out-Null
            }
        }

        $changeRecord.AfterState = @{
            GpoExists    = $true
            GpoId        = $gpo.Id
            ServerValue  = 1
            ClientValue  = 1
            LinkedAtRoot = [bool]$LinkAtDomainRoot
        }
        $changeRecord.Success = $true

        Write-ADHLog -Level FIX -Message 'ADH-003 SMB Signing Required - FIX applied successfully' -Console
    }
    catch {
        $changeRecord.ErrorMessage = $_.Exception.Message
        Write-ADHLog -Level ERROR -Message "ADH-003 fix failed: $($_.Exception.Message)" -Console
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
