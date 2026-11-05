$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$toolsDir = Join-Path $repoRoot '.tools'
$pgDir = Join-Path $toolsDir 'pgsql'
$pgBin = Join-Path $pgDir 'bin'
$pgData = Join-Path $toolsDir 'pgdata16'
$zipPath = Join-Path $toolsDir 'postgresql-16-win64.zip'

if (-not (Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
}

if (-not (Test-Path (Join-Path $pgBin 'pg_ctl.exe'))) {
    Write-Host "[PostgreSQL 16] Downloading portable PostgreSQL 16.4 Windows x64 binaries to .tools/pgsql ..."
    $url = 'https://get.enterprisedb.com/postgresql/postgresql-16.4-1-windows-x64-binaries.zip'
    & curl.exe -fSL $url -o $zipPath
    & tar.exe -xf $zipPath -C $toolsDir pgsql/bin pgsql/lib pgsql/share
    Remove-Item -Force $zipPath -ErrorAction SilentlyContinue
}

$initdb = Join-Path $pgBin 'initdb.exe'
$pgCtl = Join-Path $pgBin 'pg_ctl.exe'
$createdb = Join-Path $pgBin 'createdb.exe'
$psql = Join-Path $pgBin 'psql.exe'

if (-not (Test-Path (Join-Path $pgData 'PG_VERSION'))) {
    Write-Host "[PostgreSQL 16] Initializing local cluster at $pgData ..."
    & $initdb -D $pgData -U postgres -A trust --encoding=UTF8 --locale=C | Out-Null
}

$pgIsReady = Join-Path $pgBin 'pg_isready.exe'
$postgresExe = Join-Path $pgBin 'postgres.exe'
& $pgIsReady -h 127.0.0.1 -p 54329 -U postgres > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    $pidFile = Join-Path $pgData 'postmaster.pid'
    if (Test-Path $pidFile) {
        Remove-Item -Force $pidFile -ErrorAction SilentlyContinue
    }
    $logFile = Join-Path $toolsDir 'postgres16.log'
    Write-Host "[PostgreSQL 16] Starting PostgreSQL 16 server on 127.0.0.1:54329 ..."
    Start-Process -FilePath $postgresExe -ArgumentList "-D `"$pgData`" -p 54329 -h 127.0.0.1" -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err" -WindowStyle Hidden
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 250
        & $pgIsReady -h 127.0.0.1 -p 54329 -U postgres > $null 2>&1
        if ($LASTEXITCODE -eq 0) { break }
    }
}

$dbCheck = & $psql -h 127.0.0.1 -p 54329 -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname = 'hegosentinel'" 2>$null
if ($dbCheck -ne '1') {
    Write-Host "[PostgreSQL 16] Creating database 'hegosentinel' ..."
    & $createdb -h 127.0.0.1 -p 54329 -U postgres hegosentinel
}

Write-Host "[PostgreSQL 16] Ready on 127.0.0.1:54329 (database=hegosentinel, user=postgres)"
