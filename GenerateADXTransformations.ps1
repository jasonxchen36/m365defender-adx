<#
.SYNOPSIS
  Generates Kusto transformation scripts for Microsoft 365 Defender tables in Azure Data Explorer.

.DESCRIPTION
  For a given list of M365 Defender table names, this script:
    - Pulls schema via Microsoft Graph Threat Hunting API
    - Generates Kusto commands to:
        • Create <TableName>Raw table (if absent) with a dynamic column
        • Create JSON ingestion mapping
        • Set 1-day retention on Raw table
        • Create formatted <TableName> table with schema & 365-day retention
        • Create expand function for Raw table
        • Add update policy to populate formatted table from Raw

.PARAMETER tenantId
  Azure AD tenant ID (required)

.PARAMETER appId
  App registration (client) ID with ThreatHunting.Read.All permission (required)

.PARAMETER appSecret
  App registration secret (required)

.PARAMETER tables
  Comma-separated list of table names (optional, defaults to all supported Defender tables)

.PARAMETER outputFile
  Path to save generated Kusto script (optional)

.PARAMETER showScript
  Show generated script on screen (switch)

.PARAMETER execute
  If supplied, pushes script to ADX using Invoke-AzKustoCommand (requires Az.Kusto)

.PARAMETER clusterUri
  ADX cluster URI (required if -execute)

.PARAMETER database
  ADX database name (required if -execute)

.EXAMPLE
  .\GenerateADXTransformations.ps1 -tenantId ... -appId ... -appSecret ... [-tables Table1,Table2] [-outputFile out.kusto] [-showScript] [-execute -clusterUri ... -database ...]
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $tenantId,
    [Parameter(Mandatory=$true)]
    [string] $appId,
    [Parameter(Mandatory=$true)]
    [string] $appSecret,
    [Parameter(Mandatory=$false)]
    [string] $tables,
    [Parameter(Mandatory=$false)]
    [string] $outputFile,
    [Parameter(Mandatory=$false)]
    [switch] $showScript,
    [Parameter(Mandatory=$false)]
    [switch] $execute,
    [Parameter(Mandatory=$false)]
    [string] $clusterUri,
    [Parameter(Mandatory=$false)]
    [string] $database
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Supported Defender tables (keep in sync with DefenderArchiveR.ps1)
$m365defenderSupportedTables = @(
    "AlertInfo",
    "AlertEvidence",
    "DeviceInfo",
    "DeviceNetworkInfo",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceLogonEvents",
    "DeviceImageLoadEvents",
    "DeviceEvents",
    "DeviceFileCertificateInfo",
    "EmailAttachmentInfo",
    "EmailEvents",
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "UrlClickEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "IdentityDirectoryEvents",
    "CloudAppEvents"
)

function Get-AccessToken {
    param(
        [string] $TenantId,
        [string] $AppId,
        [string] $AppSecret
    )
    $body = @{
        scope         = 'https://graph.microsoft.com/.default'
        client_id     = $AppId
        client_secret = $AppSecret
        grant_type    = 'client_credentials'
    }
    $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    try {
        (Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop).access_token
    } catch {
        Write-Error "Failed to obtain Graph access token: $_"
        exit 1
    }
}

function Query-M365DefenderSchema {
    param(
        [string] $AccessToken,
        [string] $TableName
    )
    $url = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    $headers = @{
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $AccessToken"
    }
    $query = "$TableName | getschema | project ColumnName, ColumnType"
    $body = ConvertTo-Json @{ Query = $query }
    $maxRetries = 3
    $retryDelay = 5
    $retryCount = 0
    while ($retryCount -lt $maxRetries) {
        try {
            $resp = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop | ConvertFrom-Json
            return $resp.Results
        } catch {
            Write-Warning "Schema query failed for $TableName (attempt $($retryCount+1)); retrying in $retryDelay seconds..."
            Start-Sleep -Seconds $retryDelay
            $retryCount++
        }
    }
    throw "Failed to retrieve schema for $TableName after $maxRetries attempts."
}

function Generate-ADXKustoStatements {
    param(
        [string] $TableName,
        [object[]] $SchemaRows,
        [string] $RawRetentionDays = "1d",
        [string] $TableRetentionDays = "365d"
    )
    $tableRaw = "${TableName}Raw"
    $tableRawMapping = "${tableRaw}Mapping"
    $tableExpand = "${TableName}Expand"

    # Columns for formatted table
    $tableColumns = @()
    $expandColumns = @()
    foreach ($col in $SchemaRows) {
        $type = $col.ColumnType
        $name = $col.ColumnName
        $tableColumns += "$name:$type"
        $expandColumns += "$name = to$type(events.properties.$name)"
    }
    $tableSchema = $tableColumns -join ","
    $expandFunction = $expandColumns -join ", "

    # Compose Kusto commands
    $cmds = @(
        ".create table $tableRaw (records:dynamic)",
        ".create-or-alter table $tableRaw ingestion json mapping '$tableRawMapping' '[{\"Column\":\"records\",\"Properties\":{\"path\":\"$.records\"}}]'",
        ".alter-merge table $tableRaw policy retention softdelete = $RawRetentionDays",
        ".create table $TableName ($tableSchema)",
        ".alter-merge table $TableName policy retention softdelete = $TableRetentionDays recoverability = enabled",
        ".create-or-alter function $tableExpand { $tableRaw | mv-expand events=records | project $expandFunction }",
        ".alter table $TableName policy update @'[ { \"Source\": \"$tableRaw\", \"Query\": \"$tableExpand()\", \"IsEnabled\": \"True\", \"IsTransactional\": true } ]'"
    )
    return $cmds -join "`n"
}

function Ensure-AzKustoModule {
    if (-not (Get-Module -ListAvailable -Name Az.Kusto)) {
        Write-Host "Az.Kusto PowerShell module not found. Installing locally..." -ForegroundColor Yellow
        try {
            Install-Module Az.Kusto -Scope CurrentUser -Force -ErrorAction Stop
        } catch {
            throw "Az.Kusto module install failed: $_"
        }
    }
    Import-Module Az.Kusto -ErrorAction Stop
}

function Invoke-ADXScript {
    param(
        [string] $Script,
        [string] $ClusterUri,
        [string] $Database
    )
    try {
        $null = Get-Command Invoke-AzKustoCommand -ErrorAction Stop
    } catch {
        throw "Az.Kusto module is not available. Please install it or run without -execute."
    }
    # Split script by lines; submit each command separately for idempotency
    $commands = $Script -split '(\r?\n){2,}' | Where-Object { $_.Trim() -ne "" }
    foreach ($cmd in $commands) {
        $trimmed = $cmd.Trim()
        if ($trimmed) {
            Write-Host "Executing:" -ForegroundColor Cyan
            Write-Host $trimmed -ForegroundColor Magenta
            try {
                Invoke-AzKustoCommand -Cluster $ClusterUri -Database $Database -Query $trimmed | Out-Null
            } catch {
                Write-Warning "Failed to execute command: $trimmed"
                Write-Warning $_
            }
        }
    }
}

# Validate -tables input and determine processing set
if ($tables) {
    $tableList = ($tables -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $invalid = $tableList | Where-Object { $m365defenderSupportedTables -notcontains $_ }
    if ($invalid.Count) {
        Write-Host "Invalid table(s): $($invalid -join ', ')" -ForegroundColor Red
        Write-Host "Supported tables: $($m365defenderSupportedTables -join ', ')" -ForegroundColor Yellow
        exit 1
    }
    $targetTables = $tableList
} else {
    $targetTables = $m365defenderSupportedTables
}

Write-Host "Generating ADX Kusto scripts for tables:" -ForegroundColor Cyan
$targetTables | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }

$token = Get-AccessToken -TenantId $tenantId -AppId $appId -AppSecret $appSecret
$allScripts = @()
foreach ($tbl in $targetTables) {
    Write-Host "Processing schema for $tbl..." -ForegroundColor DarkCyan
    $schema = Query-M365DefenderSchema -AccessToken $token -TableName $tbl
    if (-not $schema) {
        Write-Warning "No schema returned for $tbl; skipping."
        continue
    }
    $script = Generate-ADXKustoStatements -TableName $tbl -SchemaRows $schema
    $allScripts += $script
}

$finalScript = $allScripts -join "`n`n"

if ($outputFile) {
    try {
        Set-Content -Path $outputFile -Value $finalScript -Encoding UTF8
        Write-Host "Script written to $outputFile" -ForegroundColor Green
    } catch {
        Write-Error "Failed to write to $outputFile: $_"
    }
}

if ($showScript) {
    Write-Host "========== Generated Kusto Script ==========" -ForegroundColor Magenta
    Write-Host $finalScript -ForegroundColor Gray
}

if ($execute) {
    if (-not $clusterUri -or -not $database) {
        Write-Error "Both -clusterUri and -database are required for -execute."
        exit 1
    }
    try {
        Ensure-AzKustoModule
        Invoke-ADXScript -Script $finalScript -ClusterUri $clusterUri -Database $database
        Write-Host "Script executed on $clusterUri/$database" -ForegroundColor Green
    } catch {
        Write-Error $_
        exit 1
    }
} elseif (-not $showScript -and -not $outputFile) {
    Write-Host "No output option specified. Use -showScript and/or -outputFile to view/save, or -execute to run." -ForegroundColor Yellow
}