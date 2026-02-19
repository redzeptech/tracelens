param(
  [Parameter(Mandatory=$true)][string]$EvtxPath,
  [Parameter(Mandatory=$true)][string]$OutXml
)

if (!(Test-Path $EvtxPath)) {
  Write-Host "[!] EVTX not found: $EvtxPath"
  exit 2
}

# Make output directory
$outXmlFull = Resolve-Path -LiteralPath (Split-Path -Parent (Join-Path (Get-Location) $OutXml)) -ErrorAction SilentlyContinue
if (-not $outXmlFull) {
  $dir = Split-Path -Parent (Join-Path (Get-Location) $OutXml)
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$OutXmlFullPath = Join-Path (Get-Location) $OutXml
$OutXmlFullPath = [System.IO.Path]::GetFullPath($OutXmlFullPath)

$tmpDir = Join-Path (Get-Location) "output"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$tmpEvtx = Join-Path $tmpDir ("export_" + [System.IO.Path]::GetFileName($EvtxPath))

Write-Host "[+] Exporting EVTX -> temporary EVTX copy"
Write-Host "    SRC : $EvtxPath"
Write-Host "    TEMP: $tmpEvtx"

# Export a readable copy (works for channels and some protected logs)
# If this fails for Security without admin, run PowerShell as Administrator.
wevtutil epl Security "$tmpEvtx"
