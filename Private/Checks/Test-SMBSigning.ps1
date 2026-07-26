function Test-SMBSigning {
    <#
    .SYNOPSIS
        ADH-003 - Verifies SMB signing is required by GPO (server AND client).
    .DESCRIPTION
        Looks for at least one linked-and-enabled GPO that requires SMB signing
        on each of the two Security Options:
          - Microsoft network server: Digitally sign communications (always)
          - Microsoft network client: Digitally sign communications (always)
        which set, respectively:
          System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature       = 1
          System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature  = 1

        These can be expressed two ways in a GPO and the check accepts either:
          - as the named Security Option (GptTmpl.inf; how our fix writes them,
            and how GPMC shows them), surfaced in Get-GPOReport XML as a
            <SecurityOptions> node with SettingNumber=1; or
          - as a registry.pol value (Set-GPRegistryValue / "Extra Registry
            Setting"), readable with Get-GPRegistryValue.

        Both halves must be set somewhere in the linked GPO tree. They can live
        in the same GPO or be split across two; the check accumulates evidence
        for both halves and only Passes when both are covered.

        Note: Windows 11 24H2 / Server 2025 require SMB signing by default,
        but mixed-version environments still need the GPO until older
        clients are gone. The check enforces "belt and suspenders".
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-003 SMB Signing Required - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-003'
        CheckName  = 'SMB Signing Required'
        Category   = 'Relay Defenses'
        Severity   = 'High'
        References = @(
            'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing',
            'https://techcommunity.microsoft.com/blog/storageatmicrosoft/the-pitfalls-of-smb-signing/3870915',
            'MITRE ATT&CK T1557.001'
        )
    }

    $serverKey  = 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters'
    $clientKey  = 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $valueName  = 'RequireSecuritySignature'
    # Security-Option KeyName form (MACHINE\...\<value>) as it appears in
    # Get-GPOReport XML; the leaf value name is part of the key.
    $serverSecOpt = ($serverKey -replace '^HKLM\\', 'MACHINE\') + "\$valueName"
    $clientSecOpt = ($clientKey -replace '^HKLM\\', 'MACHINE\') + "\$valueName"

    try {
        $allGpos = Get-GPO -All -ErrorAction Stop

        $serverGpos = @()
        $clientGpos = @()

        foreach ($gpo in $allGpos) {
            # Pull the GPO's XML once: it carries both the link state and any
            # Security Options. (Registry.pol values are read separately via
            # Get-GPRegistryValue.)
            [xml]$report = $null
            try { [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml }
            catch { continue }

            $links = @($report.GPO.LinksTo |
                Where-Object { $_.Enabled -eq 'true' } |
                Select-Object -ExpandProperty SOMPath)
            if (-not $links) { continue }

            # Index this GPO's Security Options (KeyName -> SettingNumber).
            $secOpts = @{}
            foreach ($n in $report.SelectNodes("//*[local-name()='SecurityOptions']")) {
                $kn = $n.SelectSingleNode("*[local-name()='KeyName']")
                $sn = $n.SelectSingleNode("*[local-name()='SettingNumber']")
                if ($kn -and $sn) { $secOpts[$kn.InnerText] = [int]$sn.InnerText }
            }

            foreach ($pair in @(
                @{ Side='Server'; Key=$serverKey; SecOpt=$serverSecOpt; Bucket=[ref]$serverGpos },
                @{ Side='Client'; Key=$clientKey; SecOpt=$clientSecOpt; Bucket=[ref]$clientGpos }
            )) {
                $source = $null

                # Path 1: named Security Option (how our fix writes it).
                if ($secOpts.ContainsKey($pair.SecOpt) -and $secOpts[$pair.SecOpt] -eq 1) {
                    $source = 'SecurityOption'
                }
                else {
                    # Path 2: registry.pol value (Set-GPRegistryValue / Extra Registry Setting).
                    try {
                        $regValue = Get-GPRegistryValue -Guid $gpo.Id -Key $pair.Key -ValueName $valueName -ErrorAction Stop
                        if ($regValue.Value -eq 1) { $source = 'RegistryPolicy' }
                    }
                    catch [System.ArgumentException] { }
                }

                if (-not $source) { continue }

                $pair.Bucket.Value += [PSCustomObject]@{
                    Name     = $gpo.DisplayName
                    Id       = $gpo.Id
                    Side     = $pair.Side
                    Source   = $source
                    LinkedTo = $links
                }
            }
        }

        $evidence = @{
            AuditMethod         = 'GPO inspection: named Security Option (Get-GPOReport XML) first, then registry.pol (Get-GPRegistryValue) fallback.'
            RequiresElevation   = $false
            Limitations         = 'GPO inspection proves the policy exists, not that every host has applied it. A network probe (NetExec smb --gen-relay-list, or a manual SMB negotiate) would measure behaviour per-host; an opt-in on-the-wire probe is on the project roadmap.'
            ServerSideKey       = "$serverKey\$valueName"
            ClientSideKey       = "$clientKey\$valueName"
            ServerSideGPOs      = $serverGpos
            ClientSideGPOs      = $clientGpos
            ServerSideCovered   = ($serverGpos.Count -gt 0)
            ClientSideCovered   = ($clientGpos.Count -gt 0)
        }

        if ($serverGpos.Count -gt 0 -and $clientGpos.Count -gt 0) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description "SMB signing required by linked GPO on both sides (server: $($serverGpos.Count) GPO(s), client: $($clientGpos.Count) GPO(s))." `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-003 SMB Signing Required - PASS' -Console
        }
        else {
            $missing = @()
            if ($serverGpos.Count -eq 0) { $missing += 'server-side (LanmanServer)' }
            if ($clientGpos.Count -eq 0) { $missing += 'client-side (LanmanWorkstation)' }

            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "SMB signing not enforced by any linked GPO for: $($missing -join ' and '). Hosts will accept unsigned SMB sessions, allowing NTLM relay against SMB." `
                -Evidence $evidence `
                -RemediationSteps "In a GPO linked at the domain level, enable the Security Options 'Microsoft network server: Digitally sign communications (always)' and 'Microsoft network client: Digitally sign communications (always)'. Run: Invoke-ADHardening -Mode Implement -IncludeCheckIds ADH-003" `
                -AutoFixAvailable $true `
                -FixFunction 'Set-SMBSigningRequired'

            Write-ADHLog -Level FAIL -Message "ADH-003 SMB Signing Required - FAIL (missing: $($missing -join ', '))" -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-003 SMB Signing Required - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
