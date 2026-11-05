$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$ToolsDir = Join-Path $RepoRoot '.tools'
$BinDir = Join-Path $ToolsDir 'bin'
$TrivyCacheDir = Join-Path $ToolsDir 'trivy-cache'
$PythonInstallDir = Join-Path $ToolsDir 'python'
$UvCacheDir = Join-Path $ToolsDir 'uv-cache'
$VenvDir = Join-Path $ToolsDir 'semgrep-venv'

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $TrivyCacheDir | Out-Null
New-Item -ItemType Directory -Force -Path $PythonInstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $UvCacheDir | Out-Null

# 1. Install Trivy (Windows 64-bit)
$TrivyExe = Join-Path $BinDir 'trivy.exe'
if (-not (Test-Path $TrivyExe)) {
    Write-Host '[1/4] Resolving Trivy Windows 64-bit release asset from GitHub API...'
    $Release = Invoke-RestMethod -Uri 'https://api.github.com/repos/aquasecurity/trivy/releases/latest' -Headers @{ 'User-Agent' = 'HegoSentinel-Installer' }
    $Asset = $Release.assets | Where-Object { $_.name -match '(?i)windows-64bit\.zip$' } | Select-Object -First 1
    if (-not $Asset) {
        $Releases = Invoke-RestMethod -Uri 'https://api.github.com/repos/aquasecurity/trivy/releases?per_page=10' -Headers @{ 'User-Agent' = 'HegoSentinel-Installer' }
        foreach ($Rel in $Releases) {
            $Asset = $Rel.assets | Where-Object { $_.name -match '(?i)windows-64bit\.zip$' } | Select-Object -First 1
            if ($Asset) { break }
        }
    }
    if (-not $Asset) {
        throw 'Could not find Windows-64bit.zip asset in Trivy GitHub releases'
    }
    Write-Host "[1/4] Downloading $($Asset.name) from $($Asset.browser_download_url)..."
    $TrivyZip = Join-Path $ToolsDir $Asset.name
    Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $TrivyZip
    $TrivyExtract = Join-Path $ToolsDir 'trivy-extract'
    Expand-Archive -Path $TrivyZip -DestinationPath $TrivyExtract -Force
    Copy-Item -Path (Join-Path $TrivyExtract 'trivy.exe') -Destination $TrivyExe -Force
    Remove-Item -Path $TrivyZip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TrivyExtract -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "[1/4] Trivy version: $(& $TrivyExe --version | Select-Object -First 1)"

# 2. Warm up Trivy Vulnerability DB in .tools/trivy-cache for offline scans
if (-not (Test-Path (Join-Path $TrivyCacheDir 'db\trivy.db'))) {
    Write-Host '[2/4] Downloading Trivy vulnerability database into .tools/trivy-cache...'
    $env:TRIVY_CACHE_DIR = $TrivyCacheDir
    & $TrivyExe fs --scanners vuln --download-db-only --cache-dir $TrivyCacheDir
} else {
    Write-Host '[2/4] Trivy vulnerability database already cached in .tools/trivy-cache.'
}

# 3. Install Astral uv to provision self-contained Python 3.12 + Semgrep CE
$UvExe = Join-Path $BinDir 'uv.exe'
if (-not (Test-Path $UvExe)) {
    Write-Host '[3/4] Downloading uv (Python & package manager)...'
    $UvZip = Join-Path $ToolsDir 'uv-x86_64-pc-windows-msvc.zip'
    Invoke-WebRequest -Uri 'https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip' -OutFile $UvZip
    $UvExtract = Join-Path $ToolsDir 'uv-extract'
    Expand-Archive -Path $UvZip -DestinationPath $UvExtract -Force
    $FoundUv = Get-ChildItem -Path $UvExtract -Filter 'uv.exe' -Recurse | Select-Object -First 1
    Copy-Item -Path $FoundUv.FullName -Destination $UvExe -Force
    Remove-Item -Path $UvZip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $UvExtract -Recurse -Force -ErrorAction SilentlyContinue
}

# 4. Create workspace-local Python 3.12 venv (.tools/python + .tools/semgrep-venv) so it works inside sandbox
$env:UV_PYTHON_INSTALL_DIR = $PythonInstallDir
$env:UV_CACHE_DIR = $UvCacheDir
$PyCfg = Join-Path $VenvDir 'pyvenv.cfg'
$NeedsRebuild = $true
if (Test-Path $PyCfg) {
    $CfgText = Get-Content $PyCfg -Raw
    if ($CfgText -match '\.tools\\python') {
        $NeedsRebuild = $false
    }
}
if ($NeedsRebuild) {
    Write-Host '[4/4] Building workspace-local Python 3.12 venv (.tools/python) and installing Semgrep CE...'
    if (Test-Path $VenvDir) {
        Remove-Item -Path $VenvDir -Recurse -Force
    }
    & $UvExe python install 3.12
    & $UvExe venv $VenvDir --python 3.12
    $VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
    & $UvExe pip install --python $VenvPython semgrep
}
$SemgrepExe = Join-Path $VenvDir 'Scripts\semgrep.exe'
$env:PYTHONUTF8 = '1'
Write-Host "[4/4] Semgrep version: $(& $SemgrepExe --version | Select-Object -First 1)"
Write-Host '[DONE] Workspace-local Trivy and Semgrep CE binaries are installed in .tools/!'
