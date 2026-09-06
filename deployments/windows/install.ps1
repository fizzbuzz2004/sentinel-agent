[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $tenant_id,
    [Parameter(Mandatory = $true)] [string] $node_id,
    [Parameter(Mandatory = $true)] [string] $hub_url,
    [Parameter(Mandatory = $true)] [string] $enroll_token,
    [string] $enterprise_auth_token = $env:ENTERPRISE_AUTH_TOKEN,
    [string] $InstallDir = "$env:ProgramFiles\SentinelAgent",
    [switch] $Silent
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $env:ProgramData 'SentinelAgent\certs') | Out-Null
$binary = Join-Path $InstallDir "sentinel-agent.exe"
$serviceHost = Join-Path $InstallDir "sentinel-agent-service.exe"
if (-not (Test-Path $binary) -or -not (Test-Path $serviceHost)) {
    throw "sentinel-agent.exe and sentinel-agent-service.exe must be staged in $InstallDir before installation"
}

$config = @{
    TENANT_ID = $tenant_id
    NODE_ID = $node_id
    HUB_BASE_URL = $hub_url.TrimEnd('/')
    HUB_METRICS_URL = (($hub_url.TrimEnd('/') -replace ':8443$', ':9443') + '/agent/v1/telemetry')
    HUB_CONFIG_URL = ($hub_url.TrimEnd('/') + '/api/v1/agent/config')
    ENROLL_TOKEN = $enroll_token
    CUSTOMER_ID = '0'
    ENTERPRISE_AUTH_TOKEN = $enterprise_auth_token
    AGENT_STATE_DIR = (Join-Path $env:ProgramData 'SentinelAgent')
    AGENT_CERT_PATH = (Join-Path $env:ProgramData 'SentinelAgent\certs\agent.crt')
    AGENT_KEY_PATH = (Join-Path $env:ProgramData 'SentinelAgent\certs\agent.key')
    CA_CERT_PATH = (Join-Path $env:ProgramData 'SentinelAgent\certs\ca.crt')
}
$configPath = Join-Path $env:ProgramData 'SentinelAgent\agent.env.json'
New-Item -ItemType Directory -Force -Path (Split-Path $configPath) | Out-Null
$config | ConvertTo-Json | Set-Content -Encoding UTF8 -Path $configPath

$existing = Get-Service -Name SentinelAgent -ErrorAction SilentlyContinue
if ($existing) { Stop-Service SentinelAgent -Force -ErrorAction SilentlyContinue; sc.exe delete SentinelAgent | Out-Null }
New-Service -Name SentinelAgent -BinaryPathName "`"$serviceHost`"" -DisplayName "SentinelCore Agent" -StartupType Automatic -Description "SentinelCore Enterprise Security Agent"
Start-Service SentinelAgent
if (-not $Silent) { Write-Host "SentinelAgent installed and started." }
