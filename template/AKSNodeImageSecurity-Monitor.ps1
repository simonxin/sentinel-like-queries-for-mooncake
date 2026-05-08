<#
    .DESCRIPTION
        AKS Node Image Security Monitor for 21Vianet (Mooncake)
        Checks all AKS clusters for node image version compliance against known-patched baselines.
        Detects vulnerable nodes, checks upgrade channel configuration, and writes results 
        to Log Analytics for alerting via existing SecurityMonitoringPack pipeline.
    .NOTES
        Requires: Az.Accounts, Az.Aks, Az.ResourceGraph modules
        Uses Managed Identity for authentication.
        Results written to custom Log Analytics table: AKSNodeImageSecurity_CL
    .PARAMETER workspaceId
        Log Analytics workspace ID for writing results
    .PARAMETER patchedVersions
        Comma-separated list of known-patched VHD version identifiers (date parts)
    .PARAMETER severeCVEs
        JSON array of CVE entries to check against (id, affectedOS, fixedInVersion)
#>

param(
    [string]$workspaceId       = "3d812e4e-1ea6-4e98-bee5-069c94f97930",
    [string]$logType           = "AKSNodeImageSecurity",
    [string]$patchedVersions   = "20260501,20260508,20260515,20260522",
    [string]$severeCVEsJson    = ''  # Now reads from Automation Variable by default
)

# ============================================================
# 0. Connect & Initialize
# ============================================================
Import-Module Az.Accounts

try {
    Connect-AzAccount -Identity -Environment AzureChinaCloud | Out-Null
} catch {
    Write-Error "Cannot connect to Azure: $_"
    exit 1
}
Write-Output "[OK] Connected to Azure via Managed Identity"

# Load workspace shared key
try {
    $WorkspaceSharedKey = Get-AutomationVariable -Name "WorkspaceSharedKey"
} catch {
    Write-Error "Missing Automation Variable 'WorkspaceSharedKey': $_"
    exit 1
}

$context = Get-AzContext
$subscriptionId = $context.Subscription.Id
$tenantId = $context.Tenant.Id
Write-Output "[OK] Subscription: $subscriptionId | Tenant: $tenantId"

# Parse patched versions baseline
$patchedList = $patchedVersions -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
Write-Output "[Config] Patched VHD baselines: $($patchedList -join ', ')"

# Load CVE definitions from Log Analytics custom table (primary) or parameter (fallback)
# NOTE: Check ALL CVEs (not just Active) - GitHub issue closure ≠ vulnerability gone
#       Each CVE is checked against actual node VHD version for real mitigation status
$severeCVEs = @()

if ([string]::IsNullOrWhiteSpace($severeCVEsJson)) {
    Write-Output "[Config] Querying AKSSecCVE_CL for ALL CVE baselines..."
    $kqlQuery = @"
AKSSecCVE_CL
| summarize arg_max(TimeGenerated, *) by CVEId_s
| project id=CVEId_s, name=CVEName_s, cvss=CVSS_d, severity=Severity_s, 
          affectedOS=AffectedOS_s, notAffectedOS=NotAffectedOS_s, 
          mitigatedInVHD=MitigatedInVHD_s, component=Component_s,
          status=Status_s, issueState=IssueState_s
"@
    
    try {
        $token = (Get-AzAccessToken -ResourceUrl "https://api.loganalytics.azure.cn").Token
        $queryBody = @{ query = $kqlQuery } | ConvertTo-Json
        $queryUrl = "https://api.loganalytics.azure.cn/v1/workspaces/$workspaceId/query"
        $queryHeaders = @{
            "Authorization" = "Bearer $token"
            "Content-Type"  = "application/json"
        }
        $result = Invoke-RestMethod -Uri $queryUrl -Method Post -Headers $queryHeaders -Body $queryBody
        
        if ($result.tables[0].rows.Count -gt 0) {
            $columns = $result.tables[0].columns.name
            foreach ($row in $result.tables[0].rows) {
                $cve = @{}
                for ($i = 0; $i -lt $columns.Count; $i++) {
                    $cve[$columns[$i]] = $row[$i]
                }
                # Convert affectedOS string back to array
                $cve["affectedOS"] = ($cve["affectedOS"] -split ";\s*") | Where-Object { $_ }
                $cve["notAffectedOS"] = ($cve["notAffectedOS"] -split ";\s*") | Where-Object { $_ }
                $severeCVEs += [PSCustomObject]$cve
            }
            Write-Output "[Config] Loaded $($severeCVEs.Count) CVE(s) from AKSSecCVE_CL"
            $activeCVEs = ($severeCVEs | Where-Object { $_.status -eq "Active" }).Count
            $resolvedCVEs = ($severeCVEs | Where-Object { $_.status -ne "Active" }).Count
            Write-Output "[Config]   Active: $activeCVEs | Resolved/FixReleased: $resolvedCVEs"
            Write-Output "[Config]   All CVEs checked against node VHD version regardless of issue status"
        } else {
            Write-Warning "[Config] No CVEs found in AKSSecCVE_CL table"
        }
    } catch {
        Write-Warning "[Config] Failed to query Log Analytics: $_"
        Write-Output "[Config] Falling back to Automation Variable..."
        try {
            $severeCVEsJson = Get-AutomationVariable -Name "AKSNodeCVEBaseline"
        } catch {
            Write-Error "No CVE data available from table or variable"
            exit 1
        }
    }
}

# Fallback: parse from parameter/variable JSON
if ($severeCVEs.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($severeCVEsJson)) {
    $parsed = $severeCVEsJson | ConvertFrom-Json
    if ($parsed -isnot [System.Array]) { $parsed = @($parsed) }
    $severeCVEs = $parsed
    Write-Output "[Config] Loaded $($severeCVEs.Count) CVE(s) from parameter/variable (fallback)"
}

Write-Output "[Config] Tracking $($severeCVEs.Count) CVE(s): $(($severeCVEs | ForEach-Object { $_.id }) -join ', ')"

# ============================================================
# 1. HTTP Data Collector API Helper (same as M365 collector)
# ============================================================
function Send-LogAnalyticsData {
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$LogType,
        [string]$JsonBody,
        [string]$TimeStampField = "TimeGenerated"
    )
    
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $date = [DateTime]::UtcNow.ToString("r")
    $contentLength = [System.Text.Encoding]::UTF8.GetByteCount($JsonBody)
    
    $xHeaders = "x-ms-date:$date"
    $stringToHash = "$method`n$contentLength`n$contentType`n$xHeaders`n$resource"
    $bytesToHash = [System.Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($SharedKey)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($bytesToHash)
    $signature = [Convert]::ToBase64String($hash)
    $authorization = "SharedKey ${WorkspaceId}:${signature}"
    
    $headers = @{
        "Authorization"        = $authorization
        "Log-Type"             = $LogType
        "x-ms-date"           = $date
        "time-generated-field" = $TimeStampField
    }
    
    # 21Vianet Log Analytics endpoint
    $uri = "https://${WorkspaceId}.ods.opinsights.azure.cn/api/logs?api-version=2016-04-01"
    
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $JsonBody -UseBasicParsing
    return $response.StatusCode
}

# ============================================================
# 2. Query AKS Clusters via Azure Resource Graph
# ============================================================
Write-Output "`n[Step 2] Querying AKS clusters via Resource Graph..."

$argQuery = @"
resources
| where type == "microsoft.containerservice/managedclusters"
| project 
    clusterName = name, 
    resourceGroup, 
    location,
    subscriptionId,
    kubernetesVersion = properties.kubernetesVersion,
    nodeOsUpgradeChannel = coalesce(tostring(properties.autoUpgradeProfile.nodeOsUpgradeChannel), "Not configured"),
    clusterUpgradeChannel = coalesce(tostring(properties.autoUpgradeProfile.upgradeChannel), "Not configured"),
    powerState = properties.powerState.code,
    fqdn = properties.fqdn,
    agentPoolProfiles = properties.agentPoolProfiles
"@

try {
    $clusters = Search-AzGraph -Query $argQuery -First 1000
    Write-Output "  Found $($clusters.Count) AKS cluster(s)"
} catch {
    Write-Error "Resource Graph query failed: $_"
    # Fallback: try using Az.Aks directly
    Write-Output "  Falling back to Az.Aks module..."
    Import-Module Az.Aks -ErrorAction SilentlyContinue
    $clusters = @()
}

# ============================================================
# 3. Analyze Node Image Security Status
# ============================================================
Write-Output "`n[Step 3] Analyzing node image security status..."

$results = @()
$vulnerableCount = 0
$totalNodes = 0
$timestamp = [DateTime]::UtcNow.ToString("o")

foreach ($cluster in $clusters) {
    $clusterName = $cluster.clusterName
    $resourceGroup = $cluster.resourceGroup
    $pools = $cluster.agentPoolProfiles
    
    if (-not $pools) {
        Write-Warning "  [$clusterName] No agent pool profiles found, skipping"
        continue
    }
    
    Write-Output "  [$clusterName] ($resourceGroup) - $($pools.Count) pool(s)"
    
    foreach ($pool in $pools) {
        $totalNodes++
        $poolName = $pool.name
        $nodeImageVersion = $pool.nodeImageVersion
        $osType = $pool.osType
        $osSKU = if ($pool.osSKU) { $pool.osSKU } else { "Unknown" }
        $nodeCount = $pool.count
        $vmSize = $pool.vmSize
        $mode = $pool.mode
        
        # Determine vulnerability status
        $isVulnerable = $false
        $vulnerabilityDetails = @()
        $mitigationStatus = "Unknown"
        
        # Skip Windows nodes (not affected by CVE-2026-31431)
        if ($osType -eq "Windows") {
            $mitigationStatus = "NotAffected"
            $vulnerabilityDetails += "Windows nodes are not affected"
        }
        else {
            # Check each tracked CVE against actual node VHD version
            foreach ($cve in $severeCVEs) {
                # Check if OS is in the not-affected list
                $notAffected = $false
                foreach ($safeOS in $cve.notAffectedOS) {
                    if ($osSKU -like "*$safeOS*" -or ($osSKU -eq "AzureLinux" -and $safeOS -eq "AzureLinux 2.0" -and $nodeImageVersion -like "*mariner*")) {
                        $notAffected = $true
                        break
                    }
                }
                
                if ($notAffected) {
                    $mitigationStatus = "NotAffected"
                    $vulnerabilityDetails += "$($cve.id): OS not affected ($osSKU)"
                    continue
                }
                
                # If MitigatedInVHD is "TBD" - no fix available yet
                if ($cve.mitigatedInVHD -eq "TBD" -or [string]::IsNullOrWhiteSpace($cve.mitigatedInVHD)) {
                    if ($cve.status -eq "Active") {
                        # Active CVE with no fix → vulnerable, no mitigation available
                        $isVulnerable = $true
                        $mitigationStatus = "Vulnerable"
                        $vulnerabilityDetails += "$($cve.id) [ACTIVE]: No fix available yet - monitor for updates"
                    } else {
                        # Resolved but no VHD version recorded → assume patched in recent images
                        $vulnerabilityDetails += "$($cve.id) [Resolved]: Fix released but VHD version unknown"
                    }
                    continue
                }
                
                # Check if node image version is patched against the fix VHD version
                $isPatched = $false
                
                # Extract date part from nodeImageVersion (e.g., "AKSUbuntu-2204gen2containerd-202605.08.0" -> "20260508")
                if ($nodeImageVersion -match '(\d{6})\.?(\d{2})') {
                    $vhdDateStr = $Matches[1] + $Matches[2]  # e.g., "20260508"
                    
                    # Compare against mitigated VHD date
                    $mitigatedDate = $cve.mitigatedInVHD  # e.g., "20260413"
                    if ([int64]$vhdDateStr -ge [int64]$mitigatedDate) {
                        $isPatched = $true
                    }
                }
                
                # Also check against our patched versions list
                foreach ($pv in $patchedList) {
                    if ($nodeImageVersion -like "*$pv*") {
                        $isPatched = $true
                        break
                    }
                }
                
                if ($isPatched) {
                    if ($mitigationStatus -ne "Vulnerable") { $mitigationStatus = "Patched" }
                    $vulnerabilityDetails += "$($cve.id) [$($cve.status)]: VHD version is patched ($nodeImageVersion)"
                } else {
                    $isVulnerable = $true
                    $mitigationStatus = "Vulnerable"
                    $vulnerabilityDetails += "$($cve.id) [$($cve.status)]: Node may be vulnerable - VHD ($nodeImageVersion) predates fix ($($cve.mitigatedInVHD))"
                }
            }
        }
        
        if ($isVulnerable) { $vulnerableCount++ }
        
        # Check upgrade channel recommendation
        $upgradeChannelRisk = "Low"
        $upgradeRecommendation = ""
        $nodeOsChannel = $cluster.nodeOsUpgradeChannel
        
        if ($nodeOsChannel -eq "Not configured" -or $nodeOsChannel -eq "None") {
            $upgradeChannelRisk = "High"
            $upgradeRecommendation = "Configure nodeOsUpgradeChannel to 'SecurityPatch' or 'NodeImage' for automatic security updates"
        } elseif ($nodeOsChannel -eq "Unmanaged") {
            $upgradeChannelRisk = "Medium"
            $upgradeRecommendation = "Unmanaged channel relies on OS-level patching. Kernel updates require node reboot. Consider using kured for automated reboots."
        } elseif ($nodeOsChannel -eq "NodeImage") {
            $upgradeChannelRisk = "Low"
            $upgradeRecommendation = "NodeImage channel will receive patched VHD on next weekly release"
        } elseif ($nodeOsChannel -eq "SecurityPatch") {
            $upgradeChannelRisk = "Low"
            $upgradeRecommendation = "SecurityPatch channel will auto-apply security fixes"
        }
        
        # Build result record
        $record = @{
            TimeGenerated           = $timestamp
            ClusterName             = $clusterName
            ResourceGroup           = $resourceGroup
            Location                = $cluster.location
            SubscriptionId          = $subscriptionId
            KubernetesVersion       = $cluster.kubernetesVersion
            NodePoolName            = $poolName
            NodeImageVersion        = $nodeImageVersion
            OSType                  = $osType
            OSSKU                   = $osSKU
            VMSize                  = $vmSize
            NodeCount               = $nodeCount
            PoolMode                = $mode
            NodeOsUpgradeChannel    = $nodeOsChannel
            ClusterUpgradeChannel   = $cluster.clusterUpgradeChannel
            PowerState              = $cluster.powerState
            MitigationStatus        = $mitigationStatus
            IsVulnerable            = $isVulnerable
            VulnerabilityDetails    = ($vulnerabilityDetails -join "; ")
            UpgradeChannelRisk      = $upgradeChannelRisk
            UpgradeRecommendation   = $upgradeRecommendation
            AssessmentTime          = $timestamp
            SeverityCVEs            = ($severeCVEs | Where-Object { $_.notAffectedOS -notcontains $osSKU } | ForEach-Object { $_.id }) -join ","
        }
        
        $results += $record
        
        # Log status
        $statusIcon = switch ($mitigationStatus) {
            "Vulnerable"  { "⚠️" }
            "Patched"     { "✅" }
            "NotAffected" { "➖" }
            default       { "❓" }
        }
        Write-Output "    $statusIcon $poolName ($nodeCount nodes) | $nodeImageVersion | $mitigationStatus"
    }
}

# ============================================================
# 4. Generate Summary Record
# ============================================================
Write-Output "`n[Step 4] Generating summary..."

$summaryRecord = @{
    TimeGenerated          = $timestamp
    ClusterName            = "_SUMMARY_"
    ResourceGroup          = "_ALL_"
    Location               = ""
    SubscriptionId         = $subscriptionId
    KubernetesVersion      = ""
    NodePoolName           = "_SUMMARY_"
    NodeImageVersion       = ""
    OSType                 = ""
    OSSKU                  = ""
    VMSize                 = ""
    NodeCount              = ($results | ForEach-Object { $_.NodeCount } | Measure-Object -Sum).Sum
    PoolMode               = ""
    NodeOsUpgradeChannel   = ""
    ClusterUpgradeChannel  = ""
    PowerState             = ""
    MitigationStatus       = if ($vulnerableCount -gt 0) { "ActionRequired" } else { "AllSecure" }
    IsVulnerable           = ($vulnerableCount -gt 0)
    VulnerabilityDetails   = "Total clusters: $($clusters.Count) | Total pools: $totalNodes | Vulnerable pools: $vulnerableCount | Secure pools: $($totalNodes - $vulnerableCount)"
    UpgradeChannelRisk     = if ($vulnerableCount -gt 0) { "High" } else { "Low" }
    UpgradeRecommendation  = if ($vulnerableCount -gt 0) { "Immediate action required: Run 'az aks nodepool upgrade --node-image-only' on vulnerable pools or apply mitigation DaemonSet" } else { "All nodes are patched or not affected" }
    AssessmentTime         = $timestamp
    SeverityCVEs           = ($severeCVEs.id -join ",")
}

$results += $summaryRecord

Write-Output "  Summary: $($clusters.Count) clusters, $totalNodes pools, $vulnerableCount vulnerable"

# ============================================================
# 5. Send Results to Log Analytics
# ============================================================
Write-Output "`n[Step 5] Sending $($results.Count) records to Log Analytics..."

$jsonBody = $results | ConvertTo-Json -Depth 5
if ($results.Count -eq 1) {
    $jsonBody = "[$jsonBody]"
}

try {
    $statusCode = Send-LogAnalyticsData `
        -WorkspaceId $workspaceId `
        -SharedKey $WorkspaceSharedKey `
        -LogType $logType `
        -JsonBody $jsonBody
    
    if ($statusCode -eq 200) {
        Write-Output "  [OK] Data sent successfully ($($results.Count) records)"
    } else {
        Write-Warning "  Unexpected status code: $statusCode"
    }
} catch {
    Write-Error "  Failed to send data: $($_.Exception.Message)"
    exit 1
}

# ============================================================
# 6. Output Recommendations
# ============================================================
Write-Output "`n[Step 6] Recommendations:"

if ($vulnerableCount -gt 0) {
    Write-Output "  ⚠️  ACTION REQUIRED: $vulnerableCount node pool(s) may be vulnerable!"
    Write-Output ""
    Write-Output "  Immediate remediation options:"
    Write-Output "    1. Node Image Upgrade (recommended):"
    Write-Output "       az aks nodepool upgrade -g <RG> --cluster-name <CLUSTER> -n <POOL> --node-image-only"
    Write-Output ""
    Write-Output "    2. Apply Mitigation DaemonSet (immediate, no reboot):"
    Write-Output "       kubectl apply -f cve-2026-31431-mitigate.yaml"
    Write-Output ""
    Write-Output "    3. Configure auto-upgrade channel:"
    Write-Output "       az aks update -g <RG> -n <CLUSTER> --node-os-upgrade-channel SecurityPatch"
    Write-Output ""
    
    # List vulnerable pools
    $vulnPools = $results | Where-Object { $_.IsVulnerable -eq $true -and $_.ClusterName -ne "_SUMMARY_" }
    foreach ($vp in $vulnPools) {
        Write-Output "    → $($vp.ClusterName)/$($vp.NodePoolName): $($vp.NodeImageVersion)"
    }
} else {
    Write-Output "  ✅ All AKS node pools are patched or not affected."
    Write-Output "  Continue monitoring with scheduled runs to detect newly created unpatched nodes."
}

Write-Output "`n[Complete] AKS Node Image Security Monitor finished at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
