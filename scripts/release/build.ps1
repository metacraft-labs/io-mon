param([Parameter(Mandatory = $true)][string]$Target)
. "$env:RELEASE_TOOLS/common.ps1"
Get-ReleaseDependency 'stackable-hooks-src' 'STACKABLE_HOOKS_SRC'
Get-ReleaseDependency 'shm-queue-src' 'SHM_QUEUE_SRC'
Get-ReleaseDependency 'shm-gset-src' 'SHM_GSET_SRC'
$env:IO_MON_BUILD_MODE = 'release'
$env:IO_MON_SHIM_NIMCACHE_DIR = Join-Path (Get-Location) "build/nimcache/shim-$Target"
& bash scripts/build_shim.sh @ReleaseFlags
if ($LASTEXITCODE -ne 0) { throw 'Shim compilation failed' }
Invoke-ReleaseNim 'cmd/io_mon_snoop.nim' "$ReleaseStage/bin/io-mon.exe"
Copy-Item build/lib/librepro_monitor_shim.dll "$ReleaseStage/lib/"
Invoke-ReleaseNim 'scripts/release/probe.nim' 'build/release-probe.exe'
$env:RELEASE_SMOKE_PROBE = Join-Path (Get-Location) 'build/release-probe.exe'
Copy-Item LICENSE $ReleaseStage
Complete-Release
