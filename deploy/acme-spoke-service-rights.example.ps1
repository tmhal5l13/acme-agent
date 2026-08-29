#Requires -RunAsAdministrator
<#
.SYNOPSIS
Grants the acme-spoke service's own virtual account rights to start and
stop exactly one other named service - nothing broader - so reload_hook
can control a service like FileMaker Server without acme-spoke needing
to run as LocalSystem. The Windows analogue of acme-spoke.sudoers.example:
copy this script, edit -TargetService for your environment, and run it
once as Administrator.

Do NOT broaden the ACE this script appends beyond RP (SERVICE_START) and
WP (SERVICE_STOP). Validate the result with sc.exe sdshow before relying
on it in production - a malformed security descriptor on a service is
awkward to recover from. This script reads the target service's EXISTING
security descriptor and appends to it; it never replaces it outright,
the same "narrow, additive, nothing forgotten" spirit as the sudoers file.

.PARAMETER TargetService
The service reload_hook needs to control (its actual internal service
name, not necessarily its display name - Get-Service <DisplayName> |
Select-Object Name will show it). Example: "FileMaker Server".

.EXAMPLE
.\acme-spoke-service-rights.example.ps1 -TargetService "FileMaker Server"
#>
param(
    [Parameter(Mandatory = $true)][string]$TargetService
)

$ErrorActionPreference = "Stop"

# Must match internal/winservice.ServiceName / install-spoke.ps1's
# $ServiceName - this is the service whose virtual account is being
# granted rights, not the target being controlled.
$ServiceName = "acme-spoke"

if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Error "no service named '$ServiceName' is registered - run install-spoke.ps1 first"
    exit 1
}
if (-not (Get-Service -Name $TargetService -ErrorAction SilentlyContinue)) {
    Write-Error "no service named '$TargetService' is registered on this host - use its internal service name, not its display name (Get-Service '<display name>' | Select-Object Name)"
    exit 1
}

# Step 1: switch acme-spoke off LocalSystem onto its own virtual service
# account. A virtual service account ("NT SERVICE\<name>") is created
# automatically by Windows the first time a service references it - no
# separate user-provisioning step, and no password to manage, but it runs
# with ordinary user rights rather than LocalSystem's, so it needs
# explicit grants (steps 2-4 below) for anything beyond what a normal
# user can already do.
sc.exe config $ServiceName obj= "NT SERVICE\$ServiceName" | Out-Null
Write-Host "Configured $ServiceName to run as NT SERVICE\$ServiceName (restart the service for this to take effect if it's already running)."

# Step 2: resolve that virtual account's SID - a deterministic hash of the
# service name (S-1-5-80-...), not something you can reference by name
# directly in an SDDL string the way a well-known account like "SY" can.
$sidMatch = sc.exe showsid $ServiceName | Select-String "S-1-5-80-[0-9-]+"
if (-not $sidMatch) {
    Write-Error "could not resolve a service SID for '$ServiceName' - sc.exe showsid output was unexpected"
    exit 1
}
$sid = $sidMatch.Matches[0].Value
Write-Host "Resolved $ServiceName's virtual account SID: $sid"

# Step 3: read the target service's EXISTING security descriptor. Never
# skip this and construct a descriptor from scratch - doing so would
# silently drop whatever access SYSTEM/Administrators/the existing audit
# ACE already have, which is exactly the kind of broadening this script
# is meant to avoid.
$existingSDDL = (sc.exe sdshow $TargetService | Where-Object { $_.Trim() -ne "" } | Select-Object -First 1).Trim()
if (-not $existingSDDL) {
    Write-Error "could not read '$TargetService''s existing security descriptor via sc.exe sdshow"
    exit 1
}
Write-Host "Existing security descriptor for '$TargetService': $existingSDDL"

# Step 4: append exactly one new ACE granting SERVICE_START (RP) and
# SERVICE_STOP (WP) to acme-spoke's virtual account - nothing else. This
# is the minimum reload_hook needs to run something like
# "net stop 'FileMaker Server' && net start 'FileMaker Server'" (or the
# equivalent sc.exe/Restart-Service form).
$newACE = "(A;;RPWP;;;$sid)"
$newSDDL = "$existingSDDL$newACE"

sc.exe sdset $TargetService $newSDDL | Out-Null

Write-Host ""
Write-Host "Granted NT SERVICE\$ServiceName start/stop rights on '$TargetService'."
Write-Host "Verify with: sc.exe sdshow `"$TargetService`""
Write-Host "reload_hook can now use, for example:"
Write-Host "  net stop `"$TargetService`" && net start `"$TargetService`""
