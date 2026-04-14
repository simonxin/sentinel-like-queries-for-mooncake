
$sentinelgitpath = "C:\GitHub\Azure-Sentinel\solutions"
$exportpath = "C:\GitHub\Sentinalinsights"
$basequerypack = @"
{
    "$schema":  "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion":  "1.0.0.0",
     "parameters": {
        "name": {
            "type": "string"
        },
        "location": {
            "type": "string"
        },
        "tagsByResource": {
            "type": "object"
        }

    },
    "variables":  {
                  },
    "resources": [
        {
            "apiVersion": "2019-09-01-preview",
            "name": "[parameters('name')]",
            "location": "[parameters('location')]",
            "type": "Microsoft.OperationalInsights/queryPacks",
            "properties": {},
            "tags": "[if(contains(parameters('tagsByResource'), 'Microsoft.OperationalInsights/queryPacks'), parameters('tagsByResource')['Microsoft.OperationalInsights/queryPacks'], json('{}'))]"
        }
    ]
}
"@

$suppurtedcategory = (
    "AuditLogs",
    "AzureActivity",
    "AzureDiagnostics",
    "AzureFirewall",
    "Heartbeat",
    "MultipleDataSources",
    "SecurityAlert",
    "SecurityEvent",
    "SecurityNestedRecommendation",
    "SigninLogs",
    "Syslog",
    "ThreatIntelligenceIndicator",
    "W3CIISLog",
    "WindowsEvent",
    "WindowsFirewall",
    "OfficeActivity",
    "SQLSecurityAuditEvents",
    "MySqlAuditLogs"
)

$suppurtedconnectors = (
    'AzureActiveDirectory',
    'AzureActivity',
    'AzureMonitor(Keyvault)',
    'AzureDiagnostics',
    'AzureKeyVault',
    'AzureSql',
    'CEF',
    'AzureFirewall',
    'AzureKubernetesService',
    'SecurityEvents',
    'Syslog',
    'AzureMonitor(IIS)',
    'WAF',
    'AzureSecurityCenter',
    'WindowsSecurityEvents',
    'WindowsForwardedEvents',
    'MicrosoftThreatProtection',
    'Office365',
    'OfficeATP',
    'MicrosoftCloudAppSecurity',
    'AzureNetworkWatcher',
    'AzureMonitor(VMInsights)',
    'DNS'
)
$suppurteddatatypes = (
    'AuditLogs',
    'AzureActivity',
    'AzureDiagnostics',
    'CommonSecurityLog',
    'Syslog',
    'Heartbeat',
    'SigninLogs',
    'SecurityEvent',
    'W3CIISLog',
    'SecurityAlert',
    'WindowsEvent',
    'WindowsFirewall',
    'OfficeActivity',
    'ThreatIntelligenceIndicator',
    'SQLSecurityAuditEvents',
    'MySqlAuditLogs',
    'AzureNetworkAnalytics_CL',
    'AZFWApplicationRule',
    'AZFWNetworkRule',
    'AZFWThreatIntel',
    'AZFWDnsQuery',
    'ContainerLog',
    'KubeEvents',
    'DnsEvents'
    ) 

# script will sync detection/hunting queries from local azure sentinel git clone
# function to get file encoding format before loading the file content

function Get-Encoding
{
  param
  (
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [Alias('FullName')]
    [string]
    $Path
  )

  process 
  {
    $bom = New-Object -TypeName System.Byte[](4)
        
    $file = New-Object System.IO.FileStream($Path, 'Open', 'Read')
    
    $null = $file.Read($bom,0,4)
    $file.Close()
    $file.Dispose()
    
    $enc = [Text.Encoding]::ASCII
    if ($bom[0] -eq 0x2b -and $bom[1] -eq 0x2f -and $bom[2] -eq 0x76) 
      { $enc =  [Text.Encoding]::UTF7 }
    if ($bom[0] -eq 0xff -and $bom[1] -eq 0xfe) 
      { $enc =  [Text.Encoding]::Unicode }
    if ($bom[0] -eq 0xfe -and $bom[1] -eq 0xff) 
      { $enc =  [Text.Encoding]::BigEndianUnicode }
    if ($bom[0] -eq 0x00 -and $bom[1] -eq 0x00 -and $bom[2] -eq 0xfe -and $bom[3] -eq 0xff) 
      { $enc =  [Text.Encoding]::UTF32}
    if ($bom[0] -eq 0xef -and $bom[1] -eq 0xbb -and $bom[2] -eq 0xbf) 
      { $enc =  [Text.Encoding]::UTF8}
        
    [PSCustomObject]@{
      Encoding = $enc
      Path = $Path
    }
  }
}


# dump hunting/detection/exploration queries from solution-based structure

function Dump-Queriesfromsentinelsolution {

  param
  (
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]
    $templatePath,
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]
    $outputPath
  )


  import-module powershell-yaml
 
  $metadata = @()

  $solutionname = $templatepath.split('\')[-1] 
  # load yaml from target category folder
  $yamlfiles = dir "$templatePath" -Filter *.yaml -Recurse

 foreach ($yamlfile in $yamlfiles) {
  write-host "processing template: $($yamlfile.fullname)"

        # set query type based on folder name
        if ($yamlfile.DirectoryName.split('\')[-1] -like "Analytic*") {
            $querytype = "detection"
        } elseif ($yamlfile.DirectoryName.split('\')[-1] -like "Hunting*") {
            $querytype = "hunting"
        } elseif ($yamlfile.DirectoryName.split('\')[-1] -like "Exploration*") {
            $querytype = "exploration"
        } else {
            $querytype = "unknown"
        } 

        if ($($yamlfile | Get-Encoding).Encoding.BodyName.contains("ascii")) {
            $yamltree = get-content $yamlfile.FullName -Encoding Ascii | ConvertFrom-Yaml
        } else {
            $yamltree = get-content $yamlfile.FullName -Encoding UTF8 | ConvertFrom-Yaml
        }

        $supportedconnector = $true
        $supporteddatatype = $true

        if ($yamltree.requiredDataConnectors.count -gt 0) {
            $requiredDataConnectors = $yamltree.requiredDataConnectors
            $category = $requiredDataConnectors[0].connectorid
            # derive data table name from the first data type of the first connector
            $source = $requiredDataConnectors[0].datatypes[0]
        } else {
            $requiredDataConnectors=@{
                connectorid = $yamlfile.FullName.split('\')[-1];
                datatypes = @($yamlfile.FullName.split('\')[-1])
            }
            $category = $yamlfile.FullName.split('\')[-1]
            $source = $yamlfile.FullName.split('\')[-1]
        }

      
        foreach ($item in $requiredDataConnectors ) {
            if (!($item['connectorid'] -in  $suppurtedconnectors)) {
                    $supportedconnector = $false
                }
                foreach ($datatype in  $item['datatypes']) {
                    if (!($datatype -in  $suppurteddatatypes)) {
                        $supporteddatatype = $false
                    }
            }
        }
        

        if($supporteddatatype) {
          if($supportedconnector) {
            $supported = "yes"
          } else {
            $supported = "partial"
          }
        } else {
            $supported = "no"
        }

        $metadata += [PSCustomObject]@{
            name = $yamltree.name
            source = $source
            category = $category
            description = $yamltree.description
            severity = $yamltree.severity
            entityMappings = $yamltree.entityMappings | convertto-json -depth 10
            requiredDataConnectors  = $requiredDataConnectors | convertto-json -Depth 10
            query = $yamltree.query
            querytype = $querytype
            supported = $supported
            queryFrequency = $yamltree.queryFrequency
            queryPeriod = $yamltree.queryPeriod
        }
      
    }
  $metadata | export-csv -Encoding ASCII -NoTypeInformation -path $outputPath\$solutionname.csv -force
  Write-Host "Exported $($metadata.Count) rules to $outputPath\$solutionname.csv (detection: $(($metadata | Where-Object {$_.querytype -eq 'detection'}).Count), hunting: $(($metadata | Where-Object {$_.querytype -eq 'hunting'}).Count))"
}


# Merge all per-solution CSVs into combined detectionquery.csv and huntingquery.csv
# This bridges the gap between Dump-Queriesfromsentinelsolution output and updatesecuritypacktemplate.ps1 input

function Merge-SolutionCSVs {
  param
  (
    [Parameter(Mandatory)]
    [string]
    $csvPath,       # directory containing per-solution CSVs
    [Parameter(Mandatory)]
    [string]
    $outputPath,    # directory for combined CSVs
    [string[]]
    $solutionNames  # optional: specific solutions to merge; if empty, merge all
  )

  $allRules = @()
  
  if ($solutionNames) {
    $csvFiles = $solutionNames | ForEach-Object { Get-Item "$csvPath\$_.csv" -ErrorAction SilentlyContinue }
  } else {
    # Auto-discover: all CSVs except the combined ones
    $csvFiles = Get-ChildItem "$csvPath\*.csv" | Where-Object { 
      $_.Name -notin @('detectionquery.csv', 'huntingquery.csv', 'explorationquery.csv') 
    }
  }

  foreach ($csvFile in $csvFiles) {
    Write-Host "Merging: $($csvFile.Name)"
    $rules = Import-Csv $csvFile.FullName
    $allRules += $rules
  }

  # Split into detection and hunting, map columns to match updatesecuritypacktemplate.ps1 expectations
  # Detection CSV columns: name, source, category, description, severity, requiredDataConnectors, query, supported, queryFrequency, queryPeriod
  $detectionRules = $allRules | Where-Object { $_.querytype -eq 'detection' } | Select-Object `
    name, source, category, description, severity, requiredDataConnectors, query, supported, queryFrequency, queryPeriod

  # Hunting CSV columns: name, description, table (mapped from source), requiredDataConnectors, category, query, supported
  $huntingRules = $allRules | Where-Object { $_.querytype -eq 'hunting' } | Select-Object `
    name, description, @{Name='table';Expression={$_.source}}, requiredDataConnectors, category, query, supported

  # Load existing CSVs and merge (avoid duplicates by name)
  $existingDetection = @()
  $existingHunting = @()
  if (Test-Path "$outputPath\detectionquery.csv") {
    $existingDetection = Import-Csv "$outputPath\detectionquery.csv"
  }
  if (Test-Path "$outputPath\huntingquery.csv") {
    $existingHunting = Import-Csv "$outputPath\huntingquery.csv"
  }

  # Merge: new rules override existing ones with the same name
  $existingDetNames = @{}
  foreach ($r in $detectionRules) { $existingDetNames[$r.name] = $true }
  $mergedDetection = @($existingDetection | Where-Object { -not $existingDetNames.ContainsKey($_.name) }) + @($detectionRules)

  $existingHuntNames = @{}
  foreach ($r in $huntingRules) { $existingHuntNames[$r.name] = $true }
  $mergedHunting = @($existingHunting | Where-Object { -not $existingHuntNames.ContainsKey($_.name) }) + @($huntingRules)

  $mergedDetection | Export-Csv -Encoding ASCII -NoTypeInformation -Path "$outputPath\detectionquery.csv" -Force
  $mergedHunting | Export-Csv -Encoding ASCII -NoTypeInformation -Path "$outputPath\huntingquery.csv" -Force

  Write-Host "`nMerge complete:"
  Write-Host "  Detection rules: $($mergedDetection.Count) (existing: $($existingDetection.Count), new/updated: $($detectionRules.Count))"
  Write-Host "  Hunting rules: $($mergedHunting.Count) (existing: $($existingHunting.Count), new/updated: $($huntingRules.Count))"
}


# Convenience function: sync all solutions and merge into combined CSVs in one step

function Sync-AllSolutions {
  param
  (
    [string]$solutionsPath = $sentinelgitpath,
    [string]$outputPath = "$exportpath\query"
  )

  $solutions = Get-ChildItem $solutionsPath -Directory
  Write-Host "Found $($solutions.Count) solutions in $solutionsPath`n"

  foreach ($solution in $solutions) {
    Write-Host "=== Processing: $($solution.Name) ==="
    Dump-Queriesfromsentinelsolution -templatePath $solution.FullName -outputPath $outputPath
    Write-Host ""
  }

  Write-Host "`n=== Merging all solution CSVs ==="
  Merge-SolutionCSVs -csvPath $outputPath -outputPath $outputPath
}



# =====================================================================
# Workbook (Dashboard) sync functions
# =====================================================================

# Tables/features unavailable in 21V after MDC/Sentinel retirement
$sentinelOnlyTables = @(
    'SecurityAlert',
    'SecurityIncident',
    'BehaviorAnalytics',
    'IdentityInfo',
    'ThreatIntelligenceIndicator',
    '_GetWatchlist',
    'Watchlist'
)

# Data sources unavailable in 21V
$unavailable21VDataSources = @(
    'OfficeActivity'   # M365 integration not available
)

# Endpoint replacements for Azure China
$endpointReplacements = @{
    'management.azure.com'           = 'management.chinacloudapi.cn'
    'graph.microsoft.com'            = 'microsoftgraph.chinacloudapi.cn'
    'login.microsoftonline.com'      = 'login.chinacloudapi.cn'
    'api.loganalytics.io'            = 'api.loganalytics.azure.cn'
    'sentinel.azure.com'             = ''  # remove sentinel references
}

# Recursively remove or clean workbook items that depend on Sentinel-only tables
function Remove-SentinelItems {
    param([array]$Items)
    
    $nonSentinelTables = 'AzureDiagnostics|AuditLogs|SigninLogs|AzureActivity|SecurityEvent|Syslog|CommonSecurityLog|W3CIISLog|Heartbeat|AZFWApplicationRule|AZFWNetworkRule|AZFWThreatIntel|ContainerLog|KubeEvents|WindowsEvent|MySqlAuditLogs|SQLSecurityAuditEvents'
    
    $filtered = @()
    foreach ($item in $Items) {
        $itemJson = $item | ConvertTo-Json -Depth 30 -Compress
        
        $usesSentinel = $false
        foreach ($table in $sentinelOnlyTables) {
            if ($itemJson -match [regex]::Escape($table)) { $usesSentinel = $true }
        }
        
        if (-not $usesSentinel) {
            # No Sentinel refs at all - keep as-is, just recurse
            if ($item.content -and $item.content.items) {
                $item.content.items = @(Remove-SentinelItems -Items $item.content.items)
            }
            $filtered += $item
            continue
        }
        
        # Item has Sentinel references - decide what to do
        $usesOtherData = $itemJson -match $nonSentinelTables
        
        # For query items (type=3): 
        if ($item.type -eq 3) {
            if (-not $usesOtherData) {
                # Pure Sentinel query - remove entirely
                Write-Host "    [REMOVED] Query: $($item.name) (Sentinel-only)"
                continue
            }
            # Mixed query (e.g. "let AlertIPs = SecurityAlert ... join AzureDiagnostics")
            # Strip the Sentinel part from the KQL query
            if ($item.content -and $item.content.query) {
                $origQuery = $item.content.query
                # Remove "let Var = SecurityAlert ... | ..." lines and replace join refs
                $cleanedQuery = $origQuery -replace 'let\s+\w+\s*=\s*SecurityAlert[^|]*(\|[^\r\n]*)*[\r\n]*', ''
                $cleanedQuery = $cleanedQuery -replace 'let\s+\w+\s*=\s*SecurityIncident[^|]*(\|[^\r\n]*)*[\r\n]*', ''
                # Remove join clauses that reference Sentinel variables
                $cleanedQuery = $cleanedQuery -replace '\|\s*join\s+kind\s*=\s*\w+\s*\(\s*Alert\w+\s*\)[^\r\n]*[\r\n]*', ''
                $cleanedQuery = $cleanedQuery -replace '\|\s*extend\s+HasAlert[^\r\n]*[\r\n]*', ''
                $cleanedQuery = $cleanedQuery.Trim()
                if ($cleanedQuery -ne $origQuery) {
                    $item.content.query = $cleanedQuery
                    Write-Host "    [CLEANED] Query: $($item.name) (removed Sentinel join)"
                }
            }
            $filtered += $item
            continue
        }
        
        # For parameter items (type=9): check if the param queries Sentinel tables
        if ($item.type -eq 9) {
            if (-not $usesOtherData) {
                Write-Host "    [REMOVED] Parameter: $($item.name) (Sentinel-only)"
                continue
            }
            # Mixed parameter - keep but clean individual criteria
            if ($item.content -and $item.content.parameters) {
                $cleanedParams = @()
                foreach ($p in $item.content.parameters) {
                    $pJson = $p | ConvertTo-Json -Depth 10 -Compress
                    $pHasSentinel = $false
                    foreach ($table in $sentinelOnlyTables) {
                        if ($pJson -match [regex]::Escape($table)) { $pHasSentinel = $true }
                    }
                    if ($pHasSentinel -and -not ($pJson -match $nonSentinelTables)) {
                        Write-Host "    [REMOVED] Param criterion: $($p.name) (Sentinel-only)"
                    } else {
                        $cleanedParams += $p
                    }
                }
                $item.content.parameters = $cleanedParams
            }
            $filtered += $item
            continue
        }
        
        # For group items (type=12): recurse
        if ($item.content -and $item.content.items) {
            $item.content.items = @(Remove-SentinelItems -Items $item.content.items)
            if ($item.content.items.Count -eq 0) {
                Write-Host "    [REMOVED] Empty group: $($item.name)"
                continue
            }
        }
        
        $filtered += $item
    }
    return $filtered
}


# Convert a Sentinel workbook gallery JSON to a 21V-compatible ARM template
function Convert-WorkbookToARMTemplate {
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [string]$DisplayName,
        [switch]$RemoveSentinelDeps
    )
    
    $workbookJson = Get-Content $SourcePath -Raw -Encoding UTF8
    $workbook = $workbookJson | ConvertFrom-Json
    
    if (-not $DisplayName) {
        $DisplayName = [System.IO.Path]::GetFileNameWithoutExtension($SourcePath) -replace '[-_]', ' '
    }
    
    # Step 1: Remove Sentinel-dependent items if requested
    if ($RemoveSentinelDeps -and $workbook.items) {
        Write-Host "  Cleaning Sentinel dependencies..."
        $originalCount = ($workbook | ConvertTo-Json -Depth 30 | Select-String -Pattern 'SecurityAlert|SecurityIncident' -AllMatches).Matches.Count
        $workbook.items = @(Remove-SentinelItems -Items $workbook.items)
        $newCount = ($workbook | ConvertTo-Json -Depth 30 | Select-String -Pattern 'SecurityAlert|SecurityIncident' -AllMatches).Matches.Count
        Write-Host "  Sentinel references: $originalCount -> $newCount"
    }
    
    # Step 2: Serialize workbook content
    $serialized = $workbook | ConvertTo-Json -Depth 30 -Compress
    
    # Step 3: Apply Azure China endpoint replacements
    foreach ($kv in $endpointReplacements.GetEnumerator()) {
        if ($kv.Value) {
            $serialized = $serialized.Replace($kv.Key, $kv.Value)
        }
    }
    
    # Step 4: Escape for ARM template (double-escape backslashes, handle quotes)
    $serialized = $serialized.Replace('\', '\\').Replace('"', '\"')
    
    # Step 5: Build ARM template
    $armTemplate = [ordered]@{
        '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        parameters = [ordered]@{
            workbookDisplayName = [ordered]@{
                type = 'string'
                defaultValue = $DisplayName
            }
            workspaceResourceId = [ordered]@{
                type = 'string'
                defaultValue = ''
                metadata = [ordered]@{ description = 'Log Analytics workspace resource ID' }
            }
            location = [ordered]@{
                type = 'string'
                defaultValue = '[resourceGroup().location]'
            }
        }
        variables = [ordered]@{
            workbookId = "[guid(parameters('workbookDisplayName'), resourceGroup().id)]"
        }
        resources = @(
            [ordered]@{
                type = 'Microsoft.Insights/workbooks'
                apiVersion = '2022-04-01'
                name = "[variables('workbookId')]"
                location = "[parameters('location')]"
                kind = 'shared'
                properties = [ordered]@{
                    displayName = "[parameters('workbookDisplayName')]"
                    serializedData = 'PLACEHOLDER_SERIALIZED_DATA'
                    version = '1.0'
                    sourceId = "[parameters('workspaceResourceId')]"
                    category = 'security'
                }
            }
        )
    }
    
    # Convert to JSON and inject the serializedData (avoid double-encoding)
    $templateJson = $armTemplate | ConvertTo-Json -Depth 20
    $templateJson = $templateJson.Replace('"PLACEHOLDER_SERIALIZED_DATA"', "`"$serialized`"")
    
    # Unescape unicode characters
    $templateJson = $templateJson.Replace('\u0027', "'").Replace('\u003e', '>').Replace('\u003c', '<').Replace('\u0026', '&')
    
    $templateJson | Out-File -Encoding UTF8 -FilePath $OutputPath
    Write-Host "  Output: $OutputPath ($([math]::Round((Get-Item $OutputPath).Length/1024, 1)) KB)"
}


# Dump all workbooks from a solution, converting to 21V ARM templates
function Dump-WorkbooksFromSolution {
    param(
        [Parameter(Mandatory)]
        [string]$templatePath,
        [Parameter(Mandatory)]
        [string]$outputPath
    )
    
    $solutionName = $templatePath.Split('\')[-1]
    $workbookDir = Join-Path $templatePath 'Workbooks'
    
    if (-not (Test-Path $workbookDir)) {
        Write-Host "  No Workbooks folder found in $solutionName"
        return @()
    }
    
    $workbookFiles = Get-ChildItem $workbookDir -Filter *.json -ErrorAction SilentlyContinue
    if (-not $workbookFiles) {
        Write-Host "  No workbook JSON files in $solutionName"
        return @()
    }
    
    $results = @()
    
    foreach ($wbFile in $workbookFiles) {
        $raw = Get-Content $wbFile.FullName -Raw
        
        # Skip M365/Office workbooks (data source unavailable in 21V)
        $skipReason = $null
        foreach ($ds in $unavailable21VDataSources) {
            if ($raw -match [regex]::Escape($ds)) {
                $skipReason = "Data source '$ds' not available in 21V"
            }
        }
        if ($skipReason) {
            Write-Host "  [SKIP] $($wbFile.BaseName): $skipReason"
            $results += [PSCustomObject]@{
                Solution = $solutionName; Workbook = $wbFile.BaseName
                Status = 'skipped'; Reason = $skipReason
            }
            continue
        }
        
        # Check if Sentinel cleanup needed
        $hasSentinelDeps = $false
        foreach ($table in $sentinelOnlyTables) {
            if ($raw -match [regex]::Escape($table)) { $hasSentinelDeps = $true; break }
        }
        
        $displayName = $wbFile.BaseName -replace '[-_]', ' ' -replace 'Workbook ', ''
        $outFile = Join-Path $outputPath "$($wbFile.BaseName).json"
        
        Write-Host "  Processing: $($wbFile.BaseName) (SentinelDeps=$hasSentinelDeps)"
        
        try {
            Convert-WorkbookToARMTemplate `
                -SourcePath $wbFile.FullName `
                -OutputPath $outFile `
                -DisplayName $displayName `
                -RemoveSentinelDeps:$hasSentinelDeps
            
            $results += [PSCustomObject]@{
                Solution = $solutionName; Workbook = $wbFile.BaseName
                Status = if ($hasSentinelDeps) { 'converted-cleaned' } else { 'converted' }
                Reason = ''
            }
        } catch {
            Write-Warning "Failed to convert $($wbFile.BaseName): $($_.Exception.Message)"
            $results += [PSCustomObject]@{
                Solution = $solutionName; Workbook = $wbFile.BaseName
                Status = 'failed'; Reason = $_.Exception.Message
            }
        }
    }
    
    return $results
}


# Sync all workbooks from all solutions
function Sync-AllWorkbooks {
    param(
        [string]$solutionsPath = $sentinelgitpath,
        [string]$outputPath = "$exportpath\workbook_arm"
    )
    
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }
    
    $solutions = Get-ChildItem $solutionsPath -Directory
    Write-Host "Found $($solutions.Count) solutions in $solutionsPath`n"
    
    $allResults = @()
    foreach ($solution in $solutions) {
        Write-Host "=== $($solution.Name) ==="
        $results = Dump-WorkbooksFromSolution -templatePath $solution.FullName -outputPath $outputPath
        $allResults += $results
        Write-Host ""
    }
    
    Write-Host "`n=== Workbook Sync Summary ==="
    $allResults | Group-Object Status | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
    Write-Host ""
    $allResults | Format-Table Solution, Workbook, Status, Reason -AutoSize
    
    return $allResults
}


# Usage examples:
# 1. Process a single solution (queries):
#    Dump-Queriesfromsentinelsolution -templatePath "C:\github\Azure-Sentinel\solutions\Azure-Activity" -outputPath "C:\GitHub\Sentinalinsights\query"
#
# 2. Merge per-solution CSVs into combined detection/hunting CSVs:
#    Merge-SolutionCSVs -csvPath "C:\GitHub\Sentinalinsights\query" -outputPath "C:\GitHub\Sentinalinsights\query"
#
# 3. Sync all solutions and merge in one step:
#    Sync-AllSolutions
#
# 4. Convert a single workbook to 21V ARM template:
#    Convert-WorkbookToARMTemplate -SourcePath "C:\github\Azure-Sentinel\solutions\Azure-Activity\Workbooks\AzureActivity.json" -OutputPath "C:\output\AzureActivity.json" -DisplayName "Azure Activity" -RemoveSentinelDeps
#
# 5. Sync all workbooks from all solutions:
#    Sync-AllWorkbooks
