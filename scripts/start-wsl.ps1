param(
    [string]$Distro = "kali-linux",
    [string]$Config = "config.local.json",
    [string]$Workspace = ""
)
$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$linuxRoot = (& wsl.exe -d $Distro --exec wslpath -a $projectRoot).Trim()
if ($LASTEXITCODE -ne 0) { throw "Cannot resolve repository path in WSL" }
$serverArgs = @("-m", "kali_mcp", "--config", $Config)
if ($Workspace) { $serverArgs += @("--workspace", $Workspace) }
# Only protocol messages go to stdout. Install once with scripts/install-kali.sh first.
& wsl.exe -d $Distro --cd $linuxRoot --exec "$linuxRoot/.venv-kali/bin/python" @serverArgs
exit $LASTEXITCODE
