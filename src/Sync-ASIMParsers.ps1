<#
.SYNOPSIS
    Downloads ASIM parser ARM templates from Azure Sentinel GitHub and creates
    combined ARM templates for 21V (Azure China) deployment.
.DESCRIPTION
    For each ASIM schema (NetworkSession, Dns, WebSession):
    1. Downloads individual source parser ARM JSONs from GitHub
    2. Filters to 21V-compatible parsers only
    3. Removes Sentinel Watchlist dependencies from union parsers
    4. Outputs a combined ARM template per schema
#>

param(
    [string]$OutputDir = "C:\github\Sentinalinsights\asim_arm",
    [string]$GitHubBaseUrl = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Parsers"
)

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# === ASIM Schema Definitions ===
# Each schema defines: parsers to include for 21V, their ARM template paths

$ASIMSchemas = @{
    NetworkSession = @{
        ParserPath = "ASimNetworkSession"
        # vim (filtering) parsers - 21V compatible
        VimParsers = @(
            "vimNetworkSessionEmpty",
            "vimNetworkSessionAzureFirewall",
            "vimNetworkSessionAzureNSG",
            "vimNetworkSessionVMConnection",
            "vimNetworkSessionMicrosoftSysmon",
            "vimNetworkSessionMicrosoftSysmonWindowsEvent",
            "vimNetworkSessionMicrosoftWindowsEventFirewall",
            "vimNetworkSessionMicrosoftSecurityEventFirewall",
            "vimNetworkSessionMicrosoftLinuxSysmon",
            "vimNetworkSessionFortinetFortiGate",
            "vimNetworkSessionPaloAltoCEF",
            "vimNetworkSessionCiscoASA",
            "vimNetworkSessionCheckPointFirewall",
            "vimNetworkSessionCiscoMeraki",
            "vimNetworkSessionCiscoMerakiSyslog",
            "vimNetworkSessionSonicWallFirewall",
            "vimNetworkSessionWatchGuardFirewareOS",
            "vimNetworkSessionForcePointFirewall",
            "vimNetworkSessionBarracudaCEF",
            "vimNetworkSessionBarracudaWAF"
        )
        # ASim (non-filtering) parsers
        ASimParsers = @(
            "ASimNetworkSessionAzureFirewall",
            "ASimNetworkSessionAzureNSG",
            "ASimNetworkSessionVMConnection",
            "ASimNetworkSessionMicrosoftSysmon",
            "ASimNetworkSessionMicrosoftSysmonWindowsEvent",
            "ASimNetworkSessionMicrosoftWindowsEventFirewall",
            "ASimNetworkSessionMicrosoftSecurityEventFirewall",
            "ASimNetworkSessionMicrosoftLinuxSysmon",
            "ASimNetworkSessionFortinetFortiGate",
            "ASimNetworkSessionPaloAltoCEF",
            "ASimNetworkSessionCiscoASA",
            "ASimNetworkSessionCheckPointFirewall",
            "ASimNetworkSessionCiscoMeraki",
            "ASimNetworkSessionCiscoMerakiSyslog",
            "ASimNetworkSessionSonicWallFirewall",
            "ASimNetworkSessionWatchGuardFirewareOS",
            "ASimNetworkSessionForcePointFirewall",
            "ASimNetworkSessionBarracudaCEF",
            "ASimNetworkSessionBarracudaWAF"
        )
        # Union parsers
        UnionParsers = @("imNetworkSession", "ASimNetworkSession")
        # Excluded (not available in 21V)
        ExcludedParsers = @(
            "AWSVPC", "Microsoft365Defender", "AppGateSDP", "MD4IoTAgent", "MD4IoTSensor",
            "SentinelOne", "VectraAI", "CrowdStrikeFalconHost", "VMwareCarbonBlackCloud",
            "PaloAltoCortexDataLake", "CorelightZeek", "Native", "NTANetAnalytics",
            "IllumioSaaSCore", "CiscoISE", "CiscoFirepower", "CheckpointSmartDefense"
        )
        # Union parser filtering parameters
        UnionParams = "starttime:datetime=datetime(null), endtime:datetime=datetime(null), srcipaddr_has_any_prefix:dynamic=dynamic([]), dstipaddr_has_any_prefix:dynamic=dynamic([]), ipaddr_has_any_prefix:dynamic=dynamic([]), dstportnumber:int=int(null), hostname_has_any:dynamic=dynamic([]), dvcaction:dynamic=dynamic([]), eventresult:string='*', pack:bool=false"
        VimParamPass = "starttime, endtime, srcipaddr_has_any_prefix, dstipaddr_has_any_prefix, ipaddr_has_any_prefix, dstportnumber, hostname_has_any, dvcaction, eventresult"
    }
    Dns = @{
        ParserPath = "ASimDns"
        VimParsers = @(
            "vimDnsEmpty",
            "vimDnsAzureFirewall",
            "vimDnsMicrosoftOMS",
            "vimDnsMicrosoftSysmon",
            "vimDnsMicrosoftSysmonWindowsEvent",
            "vimDnsFortinetFortigate",
            "vimDnsMicrosoftNXlog"
        )
        ASimParsers = @(
            "ASimDnsAzureFirewall",
            "ASimDnsMicrosoftOMS",
            "ASimDnsMicrosoftSysmon",
            "ASimDnsMicrosoftSysmonWindowsEvent",
            "ASimDnsFortinetFortigate",
            "ASimDnsMicrosoftNXlog"
        )
        UnionParsers = @("imDns", "ASimDns")
        ExcludedParsers = @(
            "CiscoUmbrella", "CorelightZeek", "Gcp", "InfobloxBloxOne", "InfobloxNIOS",
            "SentinelOne", "VectraAI", "ZscalerZIA", "Native"
        )
        UnionParams = "starttime:datetime=datetime(null), endtime:datetime=datetime(null), srcipaddr:string='*', domain_has_any:dynamic=dynamic([]), responsecodename:string='*', response_has_ipv4:string='*', response_has_any_prefix:dynamic=dynamic([]), eventtype:string='Query', pack:bool=false"
        VimParamPass = "starttime, endtime, srcipaddr, domain_has_any, responsecodename, response_has_ipv4, response_has_any_prefix, eventtype"
    }
    WebSession = @{
        ParserPath = "ASimWebSession"
        VimParsers = @(
            "vimWebSessionEmpty",
            "vimWebSessionAzureFirewall",
            "vimWebSessionIIS",
            "vimWebSessionApacheHTTPServer",
            "vimWebSessionSquidProxy",
            "vimWebSessionFortinetFortiGate",
            "vimWebSessionPaloAltoCEF",
            "vimWebSessionBarracudaWAF",
            "vimWebSessionBarracudaCEF",
            "vimWebSessionCitrixNetScaler",
            "vimWebSessionF5ASM",
            "vimWebSessionSonicWallFirewall",
            "vimWebSessionCiscoMeraki"
        )
        ASimParsers = @(
            "ASimWebSessionAzureFirewall",
            "ASimWebSessionIIS",
            "ASimWebSessionApacheHTTPServer",
            "ASimWebSessionSquidProxy",
            "ASimWebSessionFortinetFortiGate",
            "ASimWebSessionPaloAltoCEF",
            "ASimWebSessionBarracudaWAF",
            "ASimWebSessionBarracudaCEF",
            "ASimWebSessionCitrixNetScaler",
            "ASimWebSessionF5ASM",
            "ASimWebSessionSonicWallFirewall",
            "ASimWebSessionCiscoMeraki"
        )
        UnionParsers = @("imWebSession", "ASimWebSession")
        ExcludedParsers = @(
            "CiscoUmbrella", "CiscoFirepower", "VectraAI", "ZscalerZIA",
            "PaloAltoCortexDataLake", "SentinelOne", "Native"
        )
        UnionParams = "starttime:datetime=datetime(null), endtime:datetime=datetime(null), srcipaddr_has_any_prefix:dynamic=dynamic([]), ipaddr_has_any_prefix:dynamic=dynamic([]), url_has_any:dynamic=dynamic([]), httpuseragent_has_any:dynamic=dynamic([]), eventresultdetails_in:dynamic=dynamic([]), eventresult:string='*', pack:bool=false"
        VimParamPass = "starttime, endtime, srcipaddr_has_any_prefix, ipaddr_has_any_prefix, url_has_any, httpuseragent_has_any, eventresultdetails_in, eventresult"
    }
}

function Download-ParserARM {
    param([string]$SchemaParserPath, [string]$ParserName)
    
    $url = "$GitHubBaseUrl/$SchemaParserPath/ARM/$ParserName/$ParserName.json"
    Write-Host "  Downloading $ParserName..." -NoNewline
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop
        Write-Host " OK" -ForegroundColor Green
        return $response
    }
    catch {
        Write-Host " FAILED ($($_.Exception.Message))" -ForegroundColor Yellow
        return $null
    }
}

function Remove-WatchlistDependency {
    param([string]$Query)
    
    # Remove the _GetWatchlist line and related DisabledParsers logic
    # Replace with a simple "let DisabledParsers=dynamic([]);" and "let ASimBuiltInDisabled=false;"
    $modified = $Query
    
    # Remove: let DisabledParsers=materialize(_GetWatchlist(...) | ... | distinct SourceSpecificParser);
    $modified = $modified -replace "let DisabledParsers=materialize\(_GetWatchlist\([^)]+\)[^;]+;\s*", "let DisabledParsers=dynamic([]);`n"
    
    # Also handle variations
    $modified = $modified -replace "let DisabledParsers=materialize\(_GetWatchlist\([^)]+\)[^;]+\| where isnotempty\(SourceSpecificParser\)\);\s*", "let DisabledParsers=dynamic([]);`n"
    
    # Replace: let ASimBuiltInDisabled=toscalar('Exclude...' in (DisabledParsers) or 'Any' in (DisabledParsers));
    $modified = $modified -replace "let ASimBuiltInDisabled=toscalar\([^;]+;\s*", "let ASimBuiltInDisabled=false;`n"
    
    # Remove _ASIM_GetWatchlistRaw references (used in some rules for custom indicators)
    $modified = $modified -replace "_ASIM_GetWatchlistRaw\([^)]+\)", "datatable(WatchlistItem:dynamic)[]"
    
    return $modified
}

function Build-UnionParserQuery {
    param(
        [string]$SchemaName,
        [string[]]$VimParsers,
        [string]$UnionParams,
        [string]$VimParamPass,
        [bool]$IsFiltering  # true for im*, false for ASim*
    )
    
    $emptyParserName = if ($IsFiltering) {
        switch ($SchemaName) {
            "NetworkSession" { "vimNetworkSessionEmpty" }
            "Dns" { "vimDnsEmpty" }
            "WebSession" { "vimWebSessionEmpty" }
        }
    } else { $null }
    
    $prefix = if ($IsFiltering) { "vim" } else { "ASim" }
    $excludePrefix = if ($IsFiltering) { "Excludevim" } else { "ExcludeASim" }
    
    # Build the query
    $lines = @()
    $lines += "// ASIM $SchemaName parser for Azure China (21V)"
    $lines += "// Auto-generated - Watchlist dependencies removed, 21V-compatible parsers only"
    $lines += "let DisabledParsers=dynamic([]);"
    $lines += "let ASimBuiltInDisabled=false;"
    
    if ($IsFiltering) {
        $lines += "let ${SchemaName}Generic=("
        $lines += "  $UnionParams)"
        $lines += "{"
        $lines += "union isfuzzy=true"
        
        # Add empty parser first
        if ($emptyParserName) {
            $lines += "  $emptyParserName"
        }
        
        # Add each source parser
        $sourceParsers = $VimParsers | Where-Object { $_ -notmatch "Empty$" }
        foreach ($p in $sourceParsers) {
            $disabledCheck = "ASimBuiltInDisabled or ('$excludePrefix$($p -replace '^vim','')' in (DisabledParsers))"
            $lines += "  , $p ($VimParamPass, $disabledCheck)"
        }
        
        $lines += "};"
        $lines += "${SchemaName}Generic(starttime=starttime, endtime=endtime, pack=pack)"
    }
    else {
        $lines += "let ${SchemaName}Generic=(pack:bool=false){"
        $lines += "union isfuzzy=true"
        
        $emptyName = switch ($SchemaName) {
            "NetworkSession" { "vimNetworkSessionEmpty" }
            "Dns" { "vimDnsEmpty" }
            "WebSession" { "vimWebSessionEmpty" }
        }
        $lines += "  $emptyName"
        
        $sourceParsers = $ASIMSchemas[$SchemaName].ASimParsers
        foreach ($p in $sourceParsers) {
            $disabledCheck = "ASimBuiltInDisabled or ('$excludePrefix$($p -replace '^ASim','')' in (DisabledParsers))"
            $lines += "  , $p ($disabledCheck)"
        }
        
        $lines += "};"
        $lines += "${SchemaName}Generic(pack=pack)"
    }
    
    return ($lines -join "\n")
}

function Build-CombinedTemplate {
    param(
        [string]$SchemaName,
        [hashtable]$SchemaConfig,
        [string]$OutputPath
    )
    
    Write-Host "`n=== Processing ASIM $SchemaName ===" -ForegroundColor Cyan
    $parserPath = $SchemaConfig.ParserPath
    $resources = @()
    $failedCount = 0
    
    # 1. Download individual source parser ARM templates
    Write-Host "`nDownloading vim (filtering) parsers..."
    foreach ($parser in $SchemaConfig.VimParsers) {
        $arm = Download-ParserARM -SchemaParserPath $parserPath -ParserName $parser
        if ($arm -and $arm.resources) {
            foreach ($res in $arm.resources) {
                # Fix the resource - ensure it uses parameters
                $resources += $res
            }
        } else { $failedCount++ }
    }
    
    Write-Host "`nDownloading ASim (non-filtering) parsers..."
    foreach ($parser in $SchemaConfig.ASimParsers) {
        $arm = Download-ParserARM -SchemaParserPath $parserPath -ParserName $parser
        if ($arm -and $arm.resources) {
            foreach ($res in $arm.resources) {
                $resources += $res
            }
        } else { $failedCount++ }
    }
    
    # 2. Build custom union parsers (with Watchlist dependencies removed)
    Write-Host "`nBuilding 21V union parsers (no Watchlist dependency)..."
    
    # im* (filtering) union parser
    $imName = $SchemaConfig.UnionParsers[0]  # e.g., "imNetworkSession"
    $imQuery = Build-UnionParserQuery -SchemaName $SchemaName -VimParsers $SchemaConfig.VimParsers `
        -UnionParams $SchemaConfig.UnionParams -VimParamPass $SchemaConfig.VimParamPass -IsFiltering $true
    
    $imResource = @{
        type = "Microsoft.OperationalInsights/workspaces/savedSearches"
        apiVersion = "2020-08-01"
        name = "[concat(parameters('Workspace'), '/$imName')]"
        location = "[parameters('WorkspaceRegion')]"
        properties = @{
            etag = "*"
            displayName = "$SchemaName ASIM filtering parser (21V)"
            category = "ASIM"
            FunctionAlias = $imName
            query = $imQuery
            FunctionParameters = $SchemaConfig.UnionParams
        }
    }
    $resources += $imResource
    
    # ASim* (non-filtering) union parser
    $asimName = $SchemaConfig.UnionParsers[1]  # e.g., "ASimNetworkSession"
    $asimQuery = Build-UnionParserQuery -SchemaName $SchemaName -VimParsers $SchemaConfig.VimParsers `
        -UnionParams $SchemaConfig.UnionParams -VimParamPass $SchemaConfig.VimParamPass -IsFiltering $false
    
    $asimResource = @{
        type = "Microsoft.OperationalInsights/workspaces/savedSearches"
        apiVersion = "2020-08-01"
        name = "[concat(parameters('Workspace'), '/$asimName')]"
        location = "[parameters('WorkspaceRegion')]"
        properties = @{
            etag = "*"
            displayName = "$SchemaName ASIM parser (21V)"
            category = "ASIM"
            FunctionAlias = $asimName
            query = $asimQuery
            FunctionParameters = "pack:bool=false"
        }
    }
    $resources += $asimResource
    
    # Note: Log Analytics does NOT allow function aliases starting with '_'.
    # Sentinel built-in functions (_Im_*, _ASim_*) cannot be replicated as saved searches.
    # Query pack rules have been updated to use imXxx() / ASimXxx() instead.
    # No wrapper functions are generated here.
    
    # 3. Process each downloaded resource - remove Watchlist dependencies in source parsers too
    Write-Host "Cleaning Watchlist dependencies from source parsers..."
    foreach ($res in $resources) {
        if ($res.properties -and $res.properties.query) {
            $originalQuery = $res.properties.query
            if ($originalQuery -match "_GetWatchlist|_ASIM_GetWatchlistRaw") {
                $res.properties.query = Remove-WatchlistDependency -Query $originalQuery
                $alias = $res.properties.FunctionAlias
                Write-Host "  Cleaned Watchlist refs from $alias" -ForegroundColor Yellow
            }
        }
    }
    
    # 4. Build combined ARM template
    $template = [ordered]@{
        '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
        contentVersion = "1.0.0.0"
        metadata = @{
            title = "ASIM $SchemaName Parsers for Azure China (21V)"
            description = "Deploys ASIM $SchemaName source parsers and union parsers as Log Analytics saved functions. Watchlist dependencies removed. Only includes parsers for data sources available in Azure China."
            prerequisites = "Log Analytics workspace"
            lastUpdateTime = (Get-Date -Format "yyyy-MM-dd")
            support = @{ tier = "Community" }
        }
        parameters = [ordered]@{
            Workspace = @{
                type = "string"
                metadata = @{ description = "Log Analytics workspace name" }
            }
            WorkspaceRegion = @{
                type = "string"
                defaultValue = "[resourceGroup().location]"
                metadata = @{ description = "Workspace region" }
            }
        }
        resources = $resources
    }
    
    $json = $template | ConvertTo-Json -Depth 30 -Compress:$false
    # Fix escaped unicode
    $json = $json -replace '\\u0026', '&'
    $json = $json -replace '\\u0027', "'"
    
    [System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.Encoding]::UTF8)
    
    Write-Host "`nGenerated: $OutputPath" -ForegroundColor Green
    Write-Host "  Total resources: $($resources.Count) (failed downloads: $failedCount)"
    Write-Host "  vim parsers: $($SchemaConfig.VimParsers.Count), ASim parsers: $($SchemaConfig.ASimParsers.Count), union: 2"
}

# === Main Execution ===
Write-Host "ASIM Parser Sync for Azure China (21V)" -ForegroundColor Cyan
Write-Host "Output: $OutputDir`n"

foreach ($schemaName in @("NetworkSession", "Dns", "WebSession")) {
    $config = $ASIMSchemas[$schemaName]
    $outputFile = Join-Path $OutputDir "asim_$($schemaName.ToLower())_21v.json"
    Build-CombinedTemplate -SchemaName $schemaName -SchemaConfig $config -OutputPath $outputFile
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Get-ChildItem $OutputDir -Filter "asim_*_21v.json" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw | ConvertFrom-Json
    Write-Host "$($_.Name): $($content.resources.Count) saved functions"
}
Write-Host "`nDone! Deploy with:"
Write-Host '  az deployment group create -g <RG> --template-file asim_networksession_21v.json --parameters Workspace=<name>' -ForegroundColor Yellow
