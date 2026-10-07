param([string]$RepositoryRoot, [ValidateSet('post-commit','post-merge','post-rewrite','post-applypatch')][string]$Event = 'post-commit')
$ErrorActionPreference = 'Stop'
try {
    if (-not $RepositoryRoot) { $RepositoryRoot = (& git rev-parse --show-toplevel 2>$null) }
    if (-not $RepositoryRoot) { throw 'Git repository unavailable' }
    & git -C $RepositoryRoot rev-parse --is-inside-work-tree 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Git repository unavailable' }
    $root = [IO.Path]::GetFullPath($RepositoryRoot)
    $configPath = Join-Path $root 'docs/docstore-commit-config.json'
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw 'Local documentation configuration unavailable; run scripts/Install-DocstoreCommitHook.ps1' }
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if (-not $config.enabled) { throw 'Commit documentation is disabled in local configuration' }
    $python = [string]$config.python_path
    if (-not [IO.Path]::IsPathRooted($python) -or -not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Configured Python runtime unavailable' }
    $engine = Join-Path $root 'master/docstore_commit.py'
    if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) { throw 'Repository documentation engine unavailable' }
    Push-Location -LiteralPath $root
    try {
        if ($Event -eq 'post-rewrite') {
            $buffer = [char[]]::new(4096)
            $builder = [Text.StringBuilder]::new()
            while (($count = [Console]::In.Read($buffer,0,$buffer.Length)) -gt 0) {
                if ($builder.Length + $count -gt 1048576) { throw 'Rewrite input exceeds bound' }
                [void]$builder.Append($buffer,0,$count)
            }
            $rewrite = $builder.ToString()
            foreach ($line in ($rewrite -split '\r?\n' | Where-Object { $_ })) {
                if ($line -notmatch '^[0-9a-f]{40}(?:[0-9a-f]{24})? [0-9a-f]{40}(?:[0-9a-f]{24})?\s*$') { throw 'Invalid Git rewrite identities' }
            }
            $rewrite | & $python $engine post-commit --event $Event
        } else { & $python $engine post-commit --event $Event }
        $result = $LASTEXITCODE
    } finally { Pop-Location }
    if ($result -ne 0) { throw 'Documentation enqueue failed' }
    exit 0
} catch {
    [Console]::Error.WriteLine('Git operation succeeded; documentation synchronization failed. Run the repository installer, then resolve git rev-parse HEAD and use master/docstore_commit.py replay --commit <full-hash> --foreground with the configured Python runtime. Raw error details withheld.')
    exit 1
}