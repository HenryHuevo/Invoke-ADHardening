function Test-ADCSMisconfig {
    <#
    .SYNOPSIS
        ADH-010 - Defers AD CS template / ESC1-15 audit to Locksmith.
    .DESCRIPTION
        We deliberately do not reimplement Locksmith. We:
          1. Check whether AD CS is installed (any pKIEnrollmentService object
             in the Configuration NC). If none -> NotApplicable.
          2. Check whether the Locksmith module is available. If not ->
             Warning with installation guidance.
          3. If available, invoke Locksmith in structured-output mode
             (Mode 2, which writes an "<prefix> ADCSIssues.CSV" file into
             the current audit run's report directory instead of only
             printing to the console) and parse that CSV for a row count.
             Full detail lives in Locksmith's own CSV, alongside the rest
             of this run's report artifacts.

        We use Mode 2 (not Mode 0) specifically because Mode 0 only writes
        to the console/information stream and returns nothing to the
        pipeline - an empty pipeline result is indistinguishable from "no
        findings" and from "we captured nothing", and treating the latter
        as Pass is a false negative. Mode 2's CSV is Locksmith's own
        affirmative record of what it found (it always writes the file,
        even with zero rows, when the scan completes without an internal
        error), so a 0-row CSV is a real "Locksmith looked and found
        nothing" signal, not just an absence of evidence.

        Locksmith is by Jake Hildreth (TrimarcJake) and is the de-facto
        community tool for ESC1-15. Credit on the banner.
    .OUTPUTS
        Standardized Invoke-ADHardening finding object.
    #>
    [CmdletBinding()]
    param()

    Write-ADHLog -Level CHECK -Message 'ADH-010 AD CS misconfigurations - starting' -Console

    $checkParams = @{
        CheckId    = 'ADH-010'
        CheckName  = 'AD CS misconfigurations (ESC1-15)'
        Category   = 'AD CS'
        Severity   = 'Critical'
        References = @(
            'https://github.com/TrimarcJake/Locksmith',
            'https://posts.specterops.io/certified-pre-owned-d95910965cd2',
            'https://github.com/GhostPack/Certify',
            'https://github.com/ly4k/Certipy'
        )
    }

    $evidence = @{
        AuditMethod       = 'Locksmith integration (deferred check) - Invoke-Locksmith -Mode 2, which writes an "<prefix> ADCSIssues.CSV" file into this run''s report directory. We parse that CSV for a row count rather than relying on Mode 0''s console-only output. Locksmith makes no AD/CA changes in Modes 0-3; the CSV write is local to the report directory, same as the rest of this audit''s own report artifacts.'
        RequiresElevation = $false
        Limitations       = 'We defer detection of ESC1-15 to Locksmith. Locksmith itself has known coverage gaps on newer ESCs - cross-check with Certipy if you have suspicions. If the installed Locksmith predates the -OutputPath parameter, or the scan completes without error but writes no CSV, we cannot affirmatively distinguish "no findings" from "nothing captured" and return Warning rather than a possibly-false Pass.'
    }

    try {
        $configNc = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $caObjects = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' } `
            -SearchBase $configNc -Properties dNSHostName, cn -ErrorAction SilentlyContinue

        $evidence.CertificateAuthorities = @($caObjects | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.cn
                DNSHostName = $_.dNSHostName
                DN          = $_.DistinguishedName
            }
        })

        if (-not $caObjects) {
            $finding = New-ADHFinding @checkParams `
                -Status 'NotApplicable' `
                -Description 'No Certification Authority found in the forest configuration. AD CS is not deployed; check skipped.' `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level INFO -Message 'ADH-010 AD CS - NotApplicable (no CA installed)' -Console
            return $finding
        }

        $locksmithModule = Get-Module -Name Locksmith -ListAvailable -ErrorAction SilentlyContinue
        $evidence.LocksmithAvailable = [bool]$locksmithModule
        if ($locksmithModule) {
            $evidence.LocksmithVersion = ($locksmithModule | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()
        }

        if (-not $locksmithModule) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Warning' `
                -Description "$($caObjects.Count) Certification Authority/Authorities detected, but the Locksmith module is not installed - cannot audit templates for ESC1-15." `
                -Evidence $evidence `
                -AffectedObjects $evidence.CertificateAuthorities.DNSHostName `
                -RemediationSteps @"
Install Locksmith (audit-only, no changes are made by Modes 0-3):
    Install-Module -Name Locksmith -Scope CurrentUser -Repository PSGallery
    Import-Module Locksmith
    Invoke-Locksmith -Mode 0       # audit-only, no changes

Then re-run Invoke-ADHardening; ADH-010 auto-invokes Locksmith once it is present.
"@ `
                -AutoFixAvailable $false

            Write-ADHLog -Level WARN -Message 'ADH-010 AD CS - WARN (CA present, Locksmith not installed)' -Console
            return $finding
        }

        Import-Module Locksmith -ErrorAction Stop

        $locksmithCmd = Get-Command -Name Invoke-Locksmith -ErrorAction Stop
        $supportsOutputPath = $locksmithCmd.Parameters.ContainsKey('OutputPath')

        if (-not $supportsOutputPath) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Warning' `
                -Description "$($caObjects.Count) Certification Authority/Authorities detected. The installed Locksmith $($evidence.LocksmithVersion) does not support structured output capture (-OutputPath / Mode 2), so this check cannot reliably tell 'no findings' apart from 'nothing captured'. Run Locksmith manually and review its console output." `
                -Evidence $evidence `
                -AffectedObjects $evidence.CertificateAuthorities.DNSHostName `
                -RemediationSteps @"
Run Locksmith directly and review the console output yourself:
    Import-Module Locksmith
    Invoke-Locksmith -Mode 0    # audit-only, no changes

Consider updating Locksmith to a version supporting -OutputPath / Mode 2 for
automated, structured auditing:
    Install-Module -Name Locksmith -Scope CurrentUser -Repository PSGallery -Force
"@ `
                -AutoFixAvailable $false

            Write-ADHLog -Level WARN -Message 'ADH-010 AD CS - WARN (Locksmith lacks -OutputPath support)' -Console
            return $finding
        }

        $outputDir = $script:ADHLogPath
        if (-not $outputDir -or -not (Test-Path -Path $outputDir -PathType Container)) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Warning' `
                -Description "$($caObjects.Count) Certification Authority/Authorities detected, but this run's report directory is not available to capture Locksmith's structured output into. Run Locksmith manually." `
                -Evidence $evidence `
                -AffectedObjects $evidence.CertificateAuthorities.DNSHostName `
                -RemediationSteps @"
Run Locksmith directly:
    Import-Module Locksmith
    Invoke-Locksmith -Mode 0    # audit-only, no changes
"@ `
                -AutoFixAvailable $false

            Write-ADHLog -Level WARN -Message 'ADH-010 AD CS - WARN (no report directory available for Locksmith output)' -Console
            return $finding
        }

        Write-ADHLog -Level INFO -Message "ADH-010: invoking Locksmith $($evidence.LocksmithVersion) (Mode 2, structured output) against $outputDir" -Console

        # Only look at CSVs written by *this* invocation - Locksmith's file
        # names are timestamped ("Locksmith yyyy-MM-dd hh-mm-ss ADCSIssues.CSV"),
        # so an invocation-start watermark reliably separates them from any
        # pre-existing file of the same shape.
        $invokeStartUtc = [DateTime]::UtcNow
        $locksmithError = $null
        try {
            Invoke-Locksmith -Mode 2 -OutputPath $outputDir -ErrorAction Stop | Out-Null
        } catch {
            $locksmithError = $_.Exception.Message
            Write-ADHLog -Level WARN -Message "Invoke-Locksmith -Mode 2 failed: $locksmithError" -Console
        }

        if ($locksmithError) {
            $evidence.LocksmithError = $locksmithError

            $finding = New-ADHFinding @checkParams `
                -Status 'Warning' `
                -Description "Locksmith invocation failed: $locksmithError. Run Locksmith manually with: Invoke-Locksmith -Mode 0" `
                -Evidence $evidence `
                -AffectedObjects $evidence.CertificateAuthorities.DNSHostName `
                -AutoFixAvailable $false

            Write-ADHLog -Level WARN -Message 'ADH-010 AD CS - WARN (Locksmith errored)' -Console
            return $finding
        }

        $csvFiles = @(Get-ChildItem -Path $outputDir -Filter '*ADCSIssues.CSV' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -ge $invokeStartUtc.AddSeconds(-2) } |
            Sort-Object LastWriteTimeUtc -Descending)

        if ($csvFiles.Count -eq 0) {
            # Locksmith completed without throwing but wrote no CSV. Its own
            # Mode 2 code path always writes the file (even 0 rows) unless an
            # internal error was swallowed - so a missing file here means we
            # cannot confirm anything. Never promote silence to Pass.
            $finding = New-ADHFinding @checkParams `
                -Status 'Warning' `
                -Description "Locksmith $($evidence.LocksmithVersion) ran without error but produced no ADCSIssues.CSV in $outputDir. Cannot affirmatively confirm zero findings - run Locksmith manually and review its console output." `
                -Evidence $evidence `
                -AffectedObjects $evidence.CertificateAuthorities.DNSHostName `
                -RemediationSteps @"
Run Locksmith directly and review the console output yourself:
    Import-Module Locksmith
    Invoke-Locksmith -Mode 0    # audit-only, no changes
"@ `
                -AutoFixAvailable $false

            Write-ADHLog -Level WARN -Message 'ADH-010 AD CS - WARN (Locksmith produced no CSV)' -Console
            return $finding
        }

        $csvFile = $csvFiles[0]
        $csvRows = @(Import-Csv -Path $csvFile.FullName -ErrorAction Stop)

        $evidence.LocksmithCsvFile  = $csvFile.Name
        $evidence.LocksmithRawCount = $csvRows.Count
        $evidence.LocksmithFindings = @($csvRows | Select-Object -First 50)  # cap to keep evidence readable

        if ($csvRows.Count -eq 0) {
            $finding = New-ADHFinding @checkParams `
                -Status 'Pass' `
                -Description "Locksmith $($evidence.LocksmithVersion) scanned $($caObjects.Count) Certification Authority/Authorities and its $($csvFile.Name) contains zero rows - no AD CS issues reported. Full CSV is in this run's report directory." `
                -Evidence $evidence `
                -AutoFixAvailable $false

            Write-ADHLog -Level PASS -Message 'ADH-010 AD CS - PASS (Locksmith CSV confirms zero findings)' -Console
        }
        else {
            $finding = New-ADHFinding @checkParams `
                -Status 'Fail' `
                -Description "Locksmith $($evidence.LocksmithVersion) reported $($csvRows.Count) AD CS finding(s) across $($caObjects.Count) Certification Authority/Authorities (see $($csvFile.Name) in this run's report directory for the full list, including DistinguishedName/Fix detail not repeated here)." `
                -Evidence $evidence `
                -AffectedObjects $evidence.CertificateAuthorities.DNSHostName `
                -RemediationSteps @"
Review the full CSV ($($csvFile.Name)) in this run's report directory, or re-run Locksmith directly for remediation detail and (optionally) its built-in fix modes:
    Import-Module Locksmith
    Invoke-Locksmith -Mode 0    # audit-only (re-confirm findings)
    Invoke-Locksmith -Mode 1    # generate fix scripts (review before applying!)

Template fixes need per-template human judgment - Invoke-ADHardening does not auto-fix here by design.
"@ `
                -AutoFixAvailable $false

            Write-ADHLog -Level FAIL -Message "ADH-010 AD CS - FAIL ($($csvRows.Count) Locksmith findings)" -Console
        }

        return $finding
    }
    catch {
        $finding = New-ADHFinding @checkParams `
            -Status 'Error' `
            -Description "Check failed to execute: $($_.Exception.Message)" `
            -Evidence @{ Exception = $_.Exception.ToString() }

        Write-ADHLog -Level ERROR -Message "ADH-010 AD CS - ERROR: $($_.Exception.Message)" -Console
        return $finding
    }
}
