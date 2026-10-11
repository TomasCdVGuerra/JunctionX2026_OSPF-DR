param([ValidateSet('setup', 'test', 'ui')][string]$Mode = 'ui')
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $projectPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $projectPython)) {
        & py -3.13 -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.13 with the Windows Python launcher first.' }
    }
    & $projectPython -c "import sys; sys.exit(0 if sys.version_info[:2] == (3, 13) else 1)"
    if ($LASTEXITCODE -ne 0) { throw '.venv must use Python 3.13. Rename the old environment and create it again.' }
    & $projectPython -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    & $projectPython scripts/check_environment.py
    if ($LASTEXITCODE -ne 0) { throw 'Environment verification failed.' }
    if ($Mode -eq 'test') {
        & $projectPython -m pytest -q
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    } elseif ($Mode -eq 'ui') {
        & $projectPython -m streamlit run dashboard.py
        if ($LASTEXITCODE -ne 0) { throw 'Dashboard exited with an error.' }
    }
} finally {
    Pop-Location
}
