[CmdletBinding()]
param(
    [string]$EvidencePath = "output/windows-acceptance.json",
    [string]$Iteration6EvidencePath = "output/iteration6/windows-ci-receipt.json",
    [string]$Iteration6ArtifactsPath = "output/iteration6/artifacts"
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "This acceptance runner requires native Windows."
}

foreach ($command in @("uv", "npm")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is missing: $command"
    }
}

function Invoke-Checked {
    param(
        [scriptblock]$Command,
        [string]$Label
    )
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

Invoke-Checked { uv sync --locked } "Python dependency sync"
Invoke-Checked { npm ci --prefix ui } "UI dependency sync"
Invoke-Checked { uv run python scripts/check_all.py } "P0 full gate"
Invoke-Checked {
    uv run python scripts/windows_acceptance.py --evidence $EvidencePath
} "Windows native acceptance"
Invoke-Checked {
    uv run python scripts/iteration6_windows_office_acceptance.py `
        --evidence $Iteration6EvidencePath `
        --artifacts $Iteration6ArtifactsPath
} "Iteration 6 Windows report acceptance"

Write-Host "Windows acceptance passed. Evidence: $EvidencePath, $Iteration6EvidencePath"
