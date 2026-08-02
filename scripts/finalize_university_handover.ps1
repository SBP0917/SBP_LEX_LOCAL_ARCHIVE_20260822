[CmdletBinding()]
param(
    [string]$PythonPath = $env:CODEX_PRIMARY_RUNTIME_PYTHON,
    [string]$ExpectedFingerprint,
    [string]$StageRoot,
    [string]$ArchivePath,
    [string]$ProposalPath = $env:SBP_LEX_GRIFFITH_PROPOSAL_PATH,
    [string]$ExpectedProposalSha256
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Stop-Handover {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    exit 1
}

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & git -C $script:RepositoryRoot @Arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Handover "Git command failed: git $($Arguments -join ' ')"
    }
}

function Get-GitText {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $value = & git -C $script:RepositoryRoot @Arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Handover "Git command failed: git $($Arguments -join ' ')"
    }
    return ($value | Out-String).Trim()
}

function Invoke-HandoverPython {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & $script:PythonExecutable -m sbp_lex.assurance.handover_regeneration @Arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Handover "University handover command failed."
    }
}

function Push-And-Verify {
    param(
        [string]$RequiredConfirmation,
        [string]$Label
    )
    $confirmation = Read-Host "Type '$RequiredConfirmation' to push the $Label commit to origin/main"
    if ($confirmation -cne $RequiredConfirmation) {
        Stop-Handover "$Label push was not explicitly confirmed."
    }
    Invoke-Git -Arguments @("push", "origin", "main")
    Invoke-Git -Arguments @("fetch", "origin", "main")
    $head = Get-GitText -Arguments @("rev-parse", "HEAD")
    $remote = Get-GitText -Arguments @("rev-parse", "origin/main")
    if ($head -cne $remote) {
        Stop-Handover "$Label commit is not synchronized to origin/main."
    }
}

$script:RepositoryRoot = (
    Resolve-Path (Join-Path $PSScriptRoot "..")
).Path

if (-not $PythonPath) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand) {
        Stop-Handover "Python was not found. Pass -PythonPath with the approved runtime."
    }
    $PythonPath = $pythonCommand.Source
}
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    Stop-Handover "Approved Python executable was not found: $PythonPath"
}
$script:PythonExecutable = (Resolve-Path -LiteralPath $PythonPath).Path

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Stop-Handover "Git was not found."
}
if (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot ".git"))) {
    Stop-Handover "This is not the canonical Git checkout."
}

if (-not $ExpectedFingerprint) {
    $ExpectedFingerprint = Read-Host "Enter the separately verified 64-character signer fingerprint"
}
if ($ExpectedFingerprint -cnotmatch "^[0-9a-f]{64}$") {
    Stop-Handover "Signer fingerprint must be exactly 64 lowercase hexadecimal characters."
}
if (-not $env:SBP_LEX_SIGNING_SECRET) {
    Stop-Handover "The production signing seed is not provisioned out of band."
}
if (-not $env:SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY) {
    Stop-Handover "The trusted public verification key is not provisioned out of band."
}
$env:SBP_LEX_EXPECTED_SIGNER_FINGERPRINT = $ExpectedFingerprint

Remove-Item Env:SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH -ErrorAction SilentlyContinue
Remove-Item Env:SBP_LEX_MEASURED_STARTUP_STATE_ROOT -ErrorAction SilentlyContinue
Remove-Item Env:SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT -ErrorAction SilentlyContinue

if (-not $StageRoot) {
    $parent = Split-Path -Parent $RepositoryRoot
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $StageRoot = Join-Path $parent "SBP_UNIVERSITY_HANDOVER_STAGE_$stamp"
}
$StageRoot = [System.IO.Path]::GetFullPath($StageRoot)

if (-not $ArchivePath) {
    $parent = Split-Path -Parent $RepositoryRoot
    $stamp = Get-Date -Format "yyyyMMdd"
    $ArchivePath = Join-Path $parent "GRIFFITH_UNIVERSITY_EVALUATION_PACKAGE_$stamp.zip"
}
$ArchivePath = [System.IO.Path]::GetFullPath($ArchivePath)

if (-not $ProposalPath) {
    $ProposalPath = Read-Host "Enter the absolute path to the controlled Griffith proposal PDF"
}
if (-not (Test-Path -LiteralPath $ProposalPath -PathType Leaf)) {
    Stop-Handover "Controlled Griffith proposal PDF was not found: $ProposalPath"
}
$ProposalPath = (Resolve-Path -LiteralPath $ProposalPath).Path
if (-not $ExpectedProposalSha256) {
    $ExpectedProposalSha256 = Read-Host "Enter the separately reviewed controlled-proposal SHA-256"
}
$ExpectedProposalSha256 = $ExpectedProposalSha256.ToLowerInvariant()
if ($ExpectedProposalSha256 -cnotmatch "^[0-9a-f]{64}$") {
    Stop-Handover "Controlled-proposal SHA-256 must be exactly 64 hexadecimal characters."
}
$actualProposalSha256 = (
    Get-FileHash -LiteralPath $ProposalPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($actualProposalSha256 -cne $ExpectedProposalSha256) {
    Stop-Handover "Controlled-proposal SHA-256 does not match the reviewed release record."
}

$branch = Get-GitText -Arguments @("branch", "--show-current")
if ($branch -cne "main") {
    Stop-Handover "The canonical branch must be main; found '$branch'."
}

$dirty = Get-GitText -Arguments @(
    "status",
    "--porcelain=v1",
    "--untracked-files=all"
)
if ($dirty) {
    if (
        $dirty -match "(?m)^[ MADRCU?!]{2} (outputs/|validation_package/)" -or
        $dirty -match "sbp_lex/runtime/approved_runtime_baselines.json"
    ) {
        Stop-Handover "Dirty generated evidence or baseline state was found before the source-hardening commit."
    }
    Write-Host "Source hardening changes to be committed:" -ForegroundColor Cyan
    Write-Host $dirty
    Invoke-Git -Arguments @("diff", "--check")
    $confirmation = Read-Host "Type 'COMMIT SOURCE HARDENING' to record only the reviewed hardening changes"
    if ($confirmation -cne "COMMIT SOURCE HARDENING") {
        Stop-Handover "Source-hardening commit was not explicitly confirmed."
    }
    Invoke-Git -Arguments @("add", "-A")
    Invoke-Git -Arguments @(
        "commit",
        "-m",
        "fix(assurance): close university handover linkage gaps"
    )
    Push-And-Verify -RequiredConfirmation "PUSH SOURCE" -Label "source-hardening"
}
else {
    $head = Get-GitText -Arguments @("rev-parse", "HEAD")
    $remote = Get-GitText -Arguments @("rev-parse", "origin/main")
    if ($head -cne $remote) {
        Stop-Handover "Clean source HEAD is not synchronized to origin/main."
    }
}

$previewText = & $PythonExecutable -m sbp_lex.assurance.handover_regeneration baseline-preview
if ($LASTEXITCODE -ne 0) {
    Stop-Handover "Successor baseline preview failed."
}
try {
    $preview = $previewText | ConvertFrom-Json
}
catch {
    Stop-Handover "Successor baseline preview was not valid JSON."
}

Write-Host "Baseline preview:" -ForegroundColor Cyan
Write-Host "  Current baseline: $($preview.current_baseline_identifier)"
Write-Host "  Measurement:      $($preview.current_measurement_digest)"
Write-Host "  Drift class:      $($preview.drift_class)"
foreach ($finding in $preview.findings) {
    Write-Host "  Finding:          $($finding.component) / $($finding.reason)"
}

if ($preview.drift_class -cne "approved") {
    $suggested = "DESKTOP_V1_UNIVERSITY_HANDOVER_$(Get-Date -Format 'yyyyMMdd')_01"
    $identifier = Read-Host "New baseline identifier [$suggested]"
    if (-not $identifier) {
        $identifier = $suggested
    }
    $approvalReference = Read-Host "Enter the owner approval reference (required; no automatic value)"
    if (-not $approvalReference) {
        Stop-Handover "An explicit baseline approval reference is required."
    }
    $exact = "APPROVE:$identifier`:RETIRE:$($preview.current_baseline_identifier)"
    $confirmation = Read-Host "Type '$exact' to approve the measured successor and retire the prior baseline"
    if ($confirmation -cne $exact) {
        Stop-Handover "Successor baseline was not explicitly approved."
    }
    Invoke-HandoverPython -Arguments @(
        "baseline-approve",
        "--identifier",
        $identifier,
        "--approval-reference",
        $approvalReference,
        "--confirmation",
        $confirmation
    )

    $baselineStatus = Get-GitText -Arguments @(
        "status",
        "--porcelain=v1",
        "--untracked-files=all"
    )
    if ($baselineStatus -cnotmatch "^[ MARC][MDARC] sbp_lex/runtime/approved_runtime_baselines.json$") {
        Stop-Handover "Baseline approval changed an unexpected repository path."
    }
    Invoke-Git -Arguments @(
        "add",
        "--",
        "sbp_lex/runtime/approved_runtime_baselines.json"
    )
    Invoke-Git -Arguments @(
        "commit",
        "-m",
        "chore(trust): approve university handover runtime baseline"
    )
    Push-And-Verify -RequiredConfirmation "PUSH BASELINE" -Label "baseline-authority"
}

Write-Host "Running the clean source assurance gate..." -ForegroundColor Cyan
& $PythonExecutable -m sbp_lex.assurance.double_triple --mode source
if ($LASTEXITCODE -ne 0) {
    Stop-Handover "Source assurance did not pass."
}

if (Test-Path -LiteralPath $StageRoot) {
    Stop-Handover "The staging directory already exists. Use a new empty path: $StageRoot"
}

Write-Host "Generating the complete evidence stage outside the repository..." -ForegroundColor Cyan
Invoke-HandoverPython -Arguments @(
    "generate",
    "--stage-root",
    $StageRoot,
    "--expected-fingerprint",
    $ExpectedFingerprint
)

Write-Host "Recording the verified evidence in one bounded evidence-only commit..." -ForegroundColor Cyan
Invoke-HandoverPython -Arguments @("record", "--stage-root", $StageRoot)
Push-And-Verify -RequiredConfirmation "PUSH EVIDENCE" -Label "evidence-recording"

Write-Host "Running final assurance and creating the triple-verified archive..." -ForegroundColor Cyan
Invoke-HandoverPython -Arguments @(
    "archive",
    "--stage-root",
    $StageRoot,
    "--output",
    $ArchivePath,
    "--proposal",
    $ProposalPath,
    "--expected-proposal-sha256",
    $ExpectedProposalSha256,
    "--expected-fingerprint",
    $ExpectedFingerprint
)

Write-Host ""
Write-Host "[PASS] CONTROLLED EVALUATION PACKAGE ASSEMBLED AND TRIPLE-VERIFIED" -ForegroundColor Green
Write-Host "Archive: $ArchivePath"
Write-Host "SHA-256: $ArchivePath.sha256"
Write-Host "Repository/source material is not included. External validation remains pending."
Write-Host "Release requires a named assessor, approved scope/confidentiality controls, and explicit owner approval."
Write-Host "Do not send the signing seed or private key. Transfer trust identity through a separate authenticated channel."
