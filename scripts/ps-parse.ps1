# Parse (never run) every PowerShell script in the lab and Packer folders; exit 1 on syntax errors.
$ErrorActionPreference = 'Stop'
$files = @(Get-ChildItem -Path lab/provision, packer/scripts -Filter *.ps1)
if ($files.Count -eq 0) { throw 'no PowerShell scripts found' }
$bad = 0
foreach ($f in $files) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    foreach ($e in $errors) { Write-Host "PARSE ERROR $($f.Name):$($e.Extent.StartLineNumber): $($e.Message)"; $bad++ }
}
Write-Host "powershell parse: $($files.Count) scripts, $bad errors"
if ($bad -gt 0) { exit 1 }
