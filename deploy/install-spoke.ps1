#Requires -RunAsAdministrator
<#
.SYNOPSIS
Registers acme-spoke as a Windows service on this host - the Windows
analogue of install-spoke.sh + acme-spoke.service. Run from an elevated
PowerShell prompt, after building acme-spoke.exe (or downloading a release)
and placing it somewhere permanent (this script does not copy it for you).

.PARAMETER BinaryPath
Full path to acme-spoke.exe.

.PARAMETER ConfigPath
Full path to this spoke's config.yaml.
#>
param(
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [Parameter(Mandatory = $true)][string]$ConfigPath
)

$ErrorActionPreference = "Stop"

# Must match internal/winservice.ServiceName exactly - the SCM dispatches a
# running process to a registered service by this name, and
# winservice.RunIfService (see cmd/acme-spoke/main.go) only activates SCM
# integration when svc.IsWindowsService() recognizes the process as having
# been started that way.
$ServiceName = "acme-spoke"

if (-not (Test-Path $BinaryPath)) {
    Write-Error "expected $BinaryPath to exist - build or download acme-spoke.exe first"
    exit 1
}
if (-not (Test-Path $ConfigPath)) {
    Write-Error "expected $ConfigPath to exist - copy deploy/spoke-config.example.yaml there and edit it first"
    exit 1
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Error "a service named '$ServiceName' already exists - remove it first (sc.exe delete $ServiceName) if you mean to reinstall"
    exit 1
}

$binPath = "`"$BinaryPath`" --config `"$ConfigPath`""

# Runs as LocalSystem by default (New-Service's default when -Credential
# isn't given) - the simplest option that works without any extra account
# provisioning, but a materially higher-privilege default than the Linux
# install (a dedicated, unprivileged system user with one narrowly scoped
# sudoers rule for the reload hook - see install-spoke.sh). LocalSystem can
# do essentially anything on the box, not just what reload_hook needs.
#
# An operator wanting the tighter equivalent should instead register this
# service to run as its own virtual service account ("NT SERVICE\acme-spoke",
# created automatically the first time a service of this name references
# it) and grant that account only the specific rights reload_hook needs
# (e.g. via sc.exe sdset on the target service's own security descriptor) -
# analogous to the sudoers rule's role on Linux. That's a per-deployment
# decision this script doesn't make for you.
New-Service -Name $ServiceName `
    -BinaryPathName $binPath `
    -DisplayName "acme-agent spoke" `
    -Description "ACME issuance and local certificate install for this host." `
    -StartupType Automatic | Out-Null

# New-Service doesn't expose failure-recovery actions; sc.exe is still the
# only built-in way to set them. Mirrors acme-spoke.service's
# Restart=on-failure / RestartSec=5s: restart after 5s on each of the first
# two failures (the SCM takes no further action once the actions list is
# exhausted, avoiding an unbounded crash-restart loop), resetting the
# failure count after a full day of healthy uptime.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000 | Out-Null

Write-Host "Installed the $ServiceName service. Next steps:"
Write-Host "  1. Copy the hub's TLS certificate to wherever config.yaml's hub_tls_cert_file points,"
Write-Host "     verifying its fingerprint first against what the hub logged on its own startup."
Write-Host "  2. Review reload_hook in $ConfigPath - it runs via cmd.exe /C, not sh -c (%VAR%, not `$VAR)."
Write-Host "  3. Start-Service $ServiceName"
Write-Host "  4. Get-EventLog -LogName Application -Source $ServiceName -Newest 20"
