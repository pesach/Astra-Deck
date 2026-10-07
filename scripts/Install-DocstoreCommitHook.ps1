#requires -Version 7.0
param([string]$RepositoryRoot, [Parameter(Mandatory)][string]$PythonPath, [Parameter(Mandatory)][string]$CodexPath)
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
function Git-Value([string[]]$Arguments) {
    $value = & git -C $script:root @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Git path resolution failed' }
    return [string]($value | Select-Object -First 1)
}
function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path rejected' }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        if (-not $parent) { break }
        $cursor = $parent.FullName
    }
}
if (-not $RepositoryRoot) { $RepositoryRoot = Split-Path -Parent $PSScriptRoot }
$script:root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\','/')
$actualRoot = [IO.Path]::GetFullPath((Git-Value @('rev-parse','--show-toplevel'))).TrimEnd('\','/')
if ($actualRoot -ne $root) { throw 'Installer requires the exact repository root' }
foreach ($runtime in @($PythonPath,$CodexPath)) {
    if (-not [IO.Path]::IsPathRooted($runtime) -or -not (Test-Path -LiteralPath $runtime -PathType Leaf)) { throw 'Exact installed runtime path required' }
}
if ([IO.Path]::GetExtension($CodexPath) -ne '.exe') { throw 'Native Codex executable required' }
foreach ($owned in @('master/docstore.py','master/docstore_commit.py','master/docstore_commit_ai.py','master/docstore_commit_schema.json','scripts/Run-DocstoreCommitHook.ps1')) {
    $ownedPath = Join-Path $root $owned
    Assert-NoReparse $ownedPath
    if (-not (Test-Path -LiteralPath $ownedPath -PathType Leaf)) { throw 'Required repository-owned hook helper missing' }
}
# Event runner is compatible with Windows PowerShell 5.1, the standard OS runtime.
# Do not rely on Codex-only PATH entries for commits from Git GUI or other shells.
$launcher = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/powershell.exe'
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw 'Standard Windows PowerShell runtime unavailable' }
Assert-NoReparse $launcher
if ($launcher -match '[^a-zA-Z0-9 :\\/_.-]') { throw 'Unsafe standard shell launcher path' }
$launcherShell = [string][char]39 + $launcher.Replace('\','/') + [string][char]39
Assert-NoReparse $root
$hooks = [IO.Path]::GetFullPath((Git-Value @('rev-parse','--path-format=absolute','--git-path','hooks')))
$common = [IO.Path]::GetFullPath((Git-Value @('rev-parse','--path-format=absolute','--git-common-dir')))
if (-not ($hooks.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or $hooks.StartsWith($common + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))) { throw 'External hooks directory requires separate reviewed ownership' }
Assert-NoReparse $hooks
$husky = $hooks.TrimEnd('\','/') -eq (Join-Path $root '.husky/_').TrimEnd('\','/')
$targetDir = if ($husky) { Join-Path $root '.husky' } else { $hooks }
Assert-NoReparse $targetDir
$docs = Join-Path $root 'docs'
Assert-NoReparse $docs
$configPath = Join-Path $docs 'docstore-commit-config.json'
Assert-NoReparse $configPath
$config = if (Test-Path -LiteralPath $configPath) { Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json -AsHashtable } else { @{} }
$allowed = @('provider','enabled','python_path','codex_path','ai_timeout_seconds','routes','model','stores')
if (@($config.Keys | Where-Object { $_ -notin $allowed }).Count) { throw 'Unknown local documentation configuration field' }
if ($config.ContainsKey('stores')) {
    if ($config.stores -isnot [array] -or $config.stores.Count -gt 256) { throw 'Owned store list requires a bounded array' }
    foreach ($store in $config.stores) {
        if ($store -isnot [string] -or $store -notmatch '^(?:docs|master)/[a-zA-Z0-9_./-]+\.sqlite$' -or ($store -split '/') -contains '..') { throw 'Invalid owned store identity' }
        Assert-NoReparse (Join-Path $root $store)
    }
}
$config.provider = 'codex'; # Publish the owned store/index/export references before enabling event workers.
Push-Location -LiteralPath $root
try {
    & $PythonPath (Join-Path $root 'master/docstore_commit.py') index | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Repository documentation index verification failed' }
} finally { Pop-Location }
$config.enabled = $true; $config.python_path = [IO.Path]::GetFullPath($PythonPath); $config.codex_path = [IO.Path]::GetFullPath($CodexPath)
$ignorePath = Join-Path $root '.gitignore'
Assert-NoReparse $ignorePath
$ignore = if (Test-Path -LiteralPath $ignorePath) { [IO.File]::ReadAllText($ignorePath) } else { '' }
$patterns = @('/docs/docstore-commit-config.json','/docs/.docstore-commit/','/docs/topics/*.sqlite','/docs/topics/*.sqlite-*','/docs/topics/*.lock/','/docs/topics/*.sqlite.writer-lock/')
$missing = @($patterns | Where-Object { ($ignore -split '\r?\n') -notcontains $_ })
if ($missing.Count) { $ignore = $ignore.TrimEnd("`r","`n") + "`n" + ($missing -join "`n") + "`n" }
# Build all entries before any mutation. Existing originals retain exact bytes.
$entries = @()
foreach ($event in @('post-commit','post-merge','post-rewrite','post-applypatch')) {
    $target = Join-Path $targetDir $event
    $backup = $target + '.docstore-original'
    Assert-NoReparse $target; Assert-NoReparse $backup
    $existing = if (Test-Path -LiteralPath $target) { [IO.File]::ReadAllBytes($target) } else { $null }
    $managed = $existing -and ([Text.Encoding]::UTF8.GetString($existing).Contains('# docstore-commit-dispatch-v1'))
    if ($existing -and -not $managed) {
        if (Test-Path -LiteralPath $backup) { throw 'Original hook backup already exists; review before installation' }
        $prefix = [Text.Encoding]::UTF8.GetString($existing)
        if (($prefix -split '\r?\n')[0] -ne '#!/bin/sh') { throw 'Existing hook interpreter needs reviewed chaining' }
    }
    $hasOriginal = ($existing -and -not $managed) -or (Test-Path -LiteralPath $backup)
    $lines = @('#!/bin/sh','# docstore-commit-dispatch-v1','original_status=0')
    if ($event -eq 'post-rewrite') { $lines += 'rewrite_input=$(head -c 1048577)'; $lines += 'if [ "${#rewrite_input}" -gt 1048576 ]; then echo "Git rewrite completed; documentation input bound exceeded." >&2; exit 1; fi' }
    $invokePrefix = if ($event -eq 'post-rewrite') { 'printf ''%s\n'' "$rewrite_input" | ' } else { '' }
    if ($hasOriginal) { $lines += 'hook_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)'; $lines += ($invokePrefix + 'sh "$hook_dir/' + $event + '.docstore-original" "$@" || original_status=$?') }
    $lines += 'repo_root=$(git rev-parse --show-toplevel) || exit 1'
    $invokePrefix = if ($event -eq 'post-rewrite') { 'printf ''%s\n'' "$rewrite_input" | ' } else { '' }
    $lines += ($invokePrefix + $launcherShell + ' -NoProfile -File "$repo_root/scripts/Run-DocstoreCommitHook.ps1" -RepositoryRoot "$repo_root" -Event ' + $event)
    $lines += 'doc_status=$?'; $lines += 'if [ "$original_status" -ne 0 ]; then exit "$original_status"; fi'; $lines += 'exit "$doc_status"'
    $expectedBody = ($lines -join "`n") + "`n"
    if ($managed -and [Text.Encoding]::UTF8.GetString($existing) -ne $expectedBody) { throw 'Managed hook content differs from reviewed dispatcher; preserve and review' }
    $entries += @{ Target=$target; Backup=$backup; Original=if ($existing -and -not $managed) {$existing} else {$null}; Body=($lines -join "`n") + "`n" }
}
New-Item -ItemType Directory -Path $docs,$targetDir -Force | Out-Null
[IO.File]::WriteAllText($ignorePath,$ignore,$utf8)
$runtime = Join-Path $docs '.docstore-commit'
Assert-NoReparse $runtime
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$receiptPath = Join-Path $runtime 'installation.json'
Assert-NoReparse $receiptPath
$receipt = @{ Complete=$false; InstalledEvents=@(); CoreHooksPathUnchanged=$true }
[IO.File]::WriteAllText($receiptPath,($receipt | ConvertTo-Json) + "`n",$utf8)
$config.enabled = $false
[IO.File]::WriteAllText($configPath,($config | ConvertTo-Json -Depth 12) + "`n",$utf8)
foreach ($entry in $entries) {
    if ($null -ne $entry.Original) {
        [IO.File]::WriteAllBytes($entry.Backup,$entry.Original)
        if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($entry.Backup))) -ne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($entry.Original))) { throw 'Preserved hook verification failed' }
    }
    [IO.File]::WriteAllText($entry.Target,$entry.Body,$utf8)
    if ([IO.File]::ReadAllText($entry.Target) -ne $entry.Body) { throw 'Hook entry verification failed' }
    $receipt.InstalledEvents += [IO.Path]::GetFileName($entry.Target)
    [IO.File]::WriteAllText($receiptPath,($receipt | ConvertTo-Json) + "`n",$utf8)

}
$afterHooks = [IO.Path]::GetFullPath((Git-Value @('rev-parse','--path-format=absolute','--git-path','hooks')))
if ($afterHooks -ne $hooks) { throw 'Effective hooks path changed unexpectedly' }
# Publish the owned store/index/export references before enabling event workers.
Push-Location -LiteralPath $root
try {
    & $PythonPath (Join-Path $root 'master/docstore_commit.py') index | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Repository documentation index verification failed' }
} finally { Pop-Location }
$config.enabled = $true
[IO.File]::WriteAllText($configPath,($config | ConvertTo-Json -Depth 12) + "`n",$utf8)
$receipt.Complete = $true
[IO.File]::WriteAllText($receiptPath,($receipt | ConvertTo-Json) + "`n",$utf8)
Write-Output ('Installed commit documentation events: ' + $entries.Count + '; existing hooks preserved; core.hooksPath unchanged.')