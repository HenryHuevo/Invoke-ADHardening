function Test-MachineAccountQuota {
    <#
    .SYNOPSIS
        ADH-002 - Verifies ms-DS-MachineAccountQuota is 0.
    .DESCRIPTION
        The default value of 10 allows any authenticated user to join up to
        10 computers to the domain, which materially aids lateral movement
        and relay primitives (Kerberos resource-based constrained delegation
        abuse, sAMAccountName spoofing, etc). The hardened value is 0.

        Pass if the domain's ms-DS-MachineAccountQuota attribute equals 0.
        Fail otherwise.
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-002 Machine Account Quota - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-002'
        CheckName  = 'Machine Account Quota = 0'
        Category   = 'Domain Object Settings'
        Severity   = 'High'
        References = @(
            'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-default-local-accounts',
            'https://www.thehacker.recipes/ad/movement/builtin-groups#ms-ds-machineaccountquota',
            'MITRE ATT&CK T1136.002'
        )
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $domainObj = Get-ADObject -Identity $domain.DistinguishedName `
            -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
        $quota = $domainObj.'ms-DS-MachineAccountQuota'

        $evidence = @{
            AuditMethod              = 'AD attribute read (ms-DS-MachineAccountQuota on the domain object)'
            RequiresElevation        = $false
            Limitations              = 'Reads the domain-wide quota only. Per-user override via SeMachineAccountPrivilege is not enumerated here.'
            DomainDN                 = $domain.DistinguishedName
            MachineAccountQuotaValue = $quota
        }

        if ($quota -eq 0) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description "ms-DS-MachineAccountQuota is 0. Standard users cannot join machines to the domain." `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-002 Machine Account Quota - PASS' -Console
        }
        else {
            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "ms-DS-MachineAccountQuota is $quota. Any authenticated user can join up to $quota machines to the domain, enabling sAMAccountName spoofing and RBCD abuse." `
                -Evidence $evidence `
                -RemediationSteps "Set the domain object ms-DS-MachineAccountQuota attribute to 0. Use a delegated admin/service account for domain joins instead. Run: Invoke-ADHardening -Mode Implement -IncludeCheckIds ADH-002" `
                -AutoFixAvailable $true `
                -FixFunction 'Set-MachineAccountQuota'

            Write-ADHLog -Level FAIL -Message "ADH-002 Machine Account Quota - FAIL (value=$quota)" -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-002 Machine Account Quota - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
