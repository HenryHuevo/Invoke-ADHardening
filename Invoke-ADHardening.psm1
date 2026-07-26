# Invoke-ADHardening module loader.
# Dot-sources all .ps1 files under Public/ and Private/.
# Exports only Public/ function names.

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Capture module version so the banner can display it.
try {
    $manifestPath = Join-Path $here 'Invoke-ADHardening.psd1'
    if (Test-Path $manifestPath) {
        $script:ADHModuleVersion = (Import-PowerShellDataFile -Path $manifestPath).ModuleVersion
    }
} catch {
    $script:ADHModuleVersion = 'dev'
}

$privateFiles = Get-ChildItem -Path (Join-Path $here 'Private') -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue
$publicFiles  = Get-ChildItem -Path (Join-Path $here 'Public')  -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue

foreach ($file in @($privateFiles) + @($publicFiles)) {
    try {
        . $file.FullName
    } catch {
        Write-Error "Failed to dot-source $($file.FullName): $($_.Exception.Message)"
        throw
    }
}

# Export only public surface.
$publicFunctionNames = $publicFiles | ForEach-Object { $_.BaseName }
if ($publicFunctionNames) {
    Export-ModuleMember -Function $publicFunctionNames
}
