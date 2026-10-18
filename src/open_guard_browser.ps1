param(
  [Parameter(Mandatory = $true)][string]$Browser,
  [Parameter(Mandatory = $true)][string]$Profile,
  [switch]$Setup
)

$root = Split-Path -Parent $PSScriptRoot
$arguments = @('--no-first-run', '--no-default-browser-check', "--user-data-dir=`"$Profile`"")
if ($Setup) {
  $setupPath = Join-Path $root 'browser_extension\setup.html'
  $arguments += [System.Uri]::new($setupPath).AbsoluteUri
} else {
  $arguments += 'https://www.google.com'
}

Start-Process -FilePath $Browser -ArgumentList $arguments
