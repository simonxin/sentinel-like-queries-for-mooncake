<#
    .DESCRIPTION
        M365 OfficeActivity Log Collector for 21Vianet (Mooncake)
        Replaces Sentinel M365 connector by using Office 365 Management Activity API
        to pull audit logs and write them to Log Analytics via HTTP Data Collector API.
    .NOTES
        Requires: Az.Accounts module
        Automation Variables (encrypted):
          - M365AppClientId       : App registration Client ID
          - M365AppClientSecret   : App registration Client Secret  
          - WorkspaceSharedKey    : Log Analytics workspace shared key
        Automation Variables (plain):
          - M365LastPollTime      : ISO 8601 timestamp of last successful poll (auto-managed)
    .PARAMETER contentTypes
        Comma-separated list of content types to collect.
        Valid: Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All
#>

param(
    [string]$workspaceId       = "3d812e4e-1ea6-4e98-bee5-069c94f97930",
    [string]$contentTypes      = "Audit.AzureActiveDirectory,Audit.Exchange,Audit.SharePoint,Audit.General",
    [int]$lookbackHours        = 1,
    [int]$maxEventsPerType     = 50000,
    [string]$logType           = "OfficeActivity365",
    [int]$batchSize            = 500,
    [switch]$InitSubscriptions
)

# ============================================================
# 0. Connect & Load Secrets
# ============================================================
Import-Module Az.Accounts

try {
    Connect-AzAccount -Identity -Environment AzureChinaCloud | Out-Null
} catch {
    Write-Error "Cannot connect to Azure: $_"
    exit 1
}
Write-Output "[OK] Connected to Azure via Managed Identity"

# Load encrypted Automation Variables
try {
    $ClientId        = Get-AutomationVariable -Name "M365AppClientId"
    $ClientSecret    = Get-AutomationVariable -Name "M365AppClientSecret"
    $WorkspaceSharedKey = Get-AutomationVariable -Name "WorkspaceSharedKey"
} catch {
    Write-Error "Missing Automation Variables: $_"
    exit 1
}

# Get tenant ID from current context
$context = Get-AzContext
$tenantId = $context.Tenant.Id
Write-Output "[OK] Tenant ID: $tenantId"

# 21Vianet-specific endpoints
$authEndpoint   = "https://login.partner.microsoftonline.cn"
$apiResource    = "https://manage.office365.cn"
$apiRoot        = "https://manage.office365.cn/api/v1.0/$tenantId/activity/feed"

# Parse content types
$typeList = $contentTypes -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
Write-Output "[Config] Content types: $($typeList -join ', ')"
Write-Output "[Config] Batch size: $batchSize | Max events/type: $maxEventsPerType"

# ============================================================
# 1. Get OAuth2 Token (Client Credentials)
# ============================================================
Write-Output "`n[Step 1] Acquiring OAuth2 token..."

$tokenUrl = "$authEndpoint/$tenantId/oauth2/token"
$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    resource      = $apiResource
}

try {
    $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -TimeoutSec 30
    $accessToken = $tokenResponse.access_token
    $apiHeaders = @{ 
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json; charset=utf-8"
    }
    Write-Output "  Token acquired, expires in $($tokenResponse.expires_in)s"
} catch {
    Write-Error "Failed to acquire token: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        try { 
            $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Error "  Detail: $($sr.ReadToEnd())" 
        } catch {}
    }
    exit 1
}

# ============================================================
# 2. Manage Subscriptions
# ============================================================
if ($InitSubscriptions) {
    Write-Output "`n[Step 2] Initializing subscriptions..."
    foreach ($ct in $typeList) {
        try {
            $subResult = Invoke-RestMethod -Method Post -Uri "$apiRoot/subscriptions/start?contentType=$ct&PublisherIdentifier=$tenantId" -Headers $apiHeaders -TimeoutSec 30
            Write-Output "  [$ct] Status: $($subResult.status)"
        } catch {
            $errMsg = $_.Exception.Message
            if ($errMsg -match "already enabled" -or $errMsg -match "400") {
                Write-Output "  [$ct] Already subscribed (OK)"
            } else {
                Write-Warning "  [$ct] Subscription failed: $errMsg"
            }
        }
    }
    
    # List current subscriptions
    try {
        $subs = Invoke-RestMethod -Uri "$apiRoot/subscriptions/list?PublisherIdentifier=$tenantId" -Headers $apiHeaders -TimeoutSec 30
        Write-Output "`n  Active subscriptions:"
        foreach ($s in $subs) {
            Write-Output "    - $($s.contentType): $($s.status)"
        }
    } catch {
        Write-Warning "  Failed to list subscriptions: $($_.Exception.Message)"
    }
}

# ============================================================
# 3. Determine Time Window
# ============================================================
Write-Output "`n[Step 3] Determining poll time window..."

# Try to read last poll time from Automation Variable
$lastPollTime = $null
try {
    $lastPollStr = Get-AutomationVariable -Name "M365LastPollTime"
    if ($lastPollStr) {
        $lastPollTime = [datetime]::Parse($lastPollStr).ToUniversalTime()
        Write-Output "  Last poll time (from variable): $($lastPollTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    }
} catch {
    Write-Output "  No M365LastPollTime variable found, using lookbackHours"
}

$endTime = [datetime]::UtcNow
# Round down to the nearest minute to avoid partial-minute edge cases
$endTime = $endTime.AddSeconds(-$endTime.Second)

if ($lastPollTime) {
    $startTime = $lastPollTime
    # Cap to 24 hours max (API limit)
    if (($endTime - $startTime).TotalHours -gt 24) {
        $startTime = $endTime.AddHours(-24)
        Write-Warning "  Time gap > 24h, capped to last 24 hours"
    }
} else {
    $startTime = $endTime.AddHours(-$lookbackHours)
}

# Ensure at least 1 minute gap
if (($endTime - $startTime).TotalMinutes -lt 1) {
    Write-Output "  Time window too small, skipping this run"
    exit 0
}

$startStr = $startTime.ToString("yyyy-MM-ddTHH:mm")
$endStr   = $endTime.ToString("yyyy-MM-ddTHH:mm")
Write-Output "  Poll window: $startStr → $endStr ($('{0:N1}' -f ($endTime - $startTime).TotalHours) hours)"

# ============================================================
# 4. HDCA Helper Function
# ============================================================
function Send-ToLogAnalytics {
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$LogType,
        [array]$LogEntries
    )
    
    if ($LogEntries.Count -eq 0) { return $true }
    
    $json = $LogEntries | ConvertTo-Json -Depth 10 -Compress
    if ($LogEntries.Count -eq 1) {
        $json = "[$json]"
    }
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    
    $rfc1123date = [datetime]::UtcNow.ToString("r")
    $contentLength = $bodyBytes.Length
    $stringToSign = "POST`n$contentLength`napplication/json; charset=utf-8`nx-ms-date:$rfc1123date`n/api/logs"
    $bytesToSign = [System.Text.Encoding]::UTF8.GetBytes($stringToSign)
    $keyBytes = [Convert]::FromBase64String($SharedKey)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $signature = [Convert]::ToBase64String($hmac.ComputeHash($bytesToSign))
    $authHeader = "SharedKey ${WorkspaceId}:$signature"
    
    $uri = "https://${WorkspaceId}.ods.opinsights.azure.cn/api/logs?api-version=2016-04-01"
    $headers = @{
        "Authorization"        = $authHeader
        "Log-Type"             = $LogType
        "x-ms-date"            = $rfc1123date
        "time-generated-field" = "TimeGenerated"
        "Content-Type"         = "application/json; charset=utf-8"
    }
    
    try {
        Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $bodyBytes -TimeoutSec 60
        return $true
    } catch {
        Write-Warning "  HDCA write failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try { 
                $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                Write-Warning "  Detail: $($sr.ReadToEnd())" 
            } catch {}
        }
        return $false
    }
}

# ============================================================
# 5. Poll & Collect Activity Logs
# ============================================================
Write-Output "`n[Step 4] Polling Office 365 Management Activity API..."

$totalEventsCollected = 0
$totalBatchesSent     = 0
$failedTypes          = @()

foreach ($contentType in $typeList) {
    Write-Output "`n  === $contentType ==="
    $typeEventCount = 0
    
    # 5a. List available content blobs
    $contentUrl = "$apiRoot/subscriptions/content?contentType=$contentType&startTime=$startStr&endTime=$endStr&PublisherIdentifier=$tenantId"
    $allContentItems = @()
    
    try {
        # Use Invoke-RestMethod for simplicity (pagination handled via retry if needed)
        $items = Invoke-RestMethod -Uri $contentUrl -Headers $apiHeaders -TimeoutSec 60 -ErrorAction Stop
        if ($items) {
            $allContentItems = @($items)
        }
        Write-Output "    Content blobs available: $($allContentItems.Count)"
    } catch {
        $errMsg = $_.Exception.Message
        $errDetail = $_.ErrorDetails.Message
        if ($errMsg -match "AF20022" -or $errDetail -match "AF20022" -or $errMsg -match "No subscription") {
            Write-Warning "    No active subscription for $contentType. Run with -InitSubscriptions first."
            $failedTypes += $contentType
            continue
        }
        # Empty response (no content available) returns empty - not an error
        if ($_.Exception.Response.StatusCode -eq 200 -or $errMsg -match "empty") {
            Write-Output "    No content blobs (empty response)"
            continue
        }
        Write-Warning "    Failed to list content: $errMsg"
        if ($errDetail) { Write-Warning "    Detail: $errDetail" }
        $failedTypes += $contentType
        continue
    }
    
    if ($allContentItems.Count -eq 0) {
        Write-Output "    No new content available"
        continue
    }
    
    # 5b. Download each content blob and extract events
    $batchBuffer = @()
    $blobsProcessed = 0
    
    foreach ($item in $allContentItems) {
        if ($typeEventCount -ge $maxEventsPerType) {
            Write-Warning "    Reached max events limit ($maxEventsPerType), stopping"
            break
        }
        
        try {
            $events = Invoke-RestMethod -Uri $item.contentUri -Headers $apiHeaders -TimeoutSec 120
        } catch {
            Write-Warning "    Failed to download blob $($item.contentId): $($_.Exception.Message)"
            continue
        }
        
        $blobsProcessed++
        
        if (-not $events) { continue }
        
        # Ensure it's an array
        if ($events -isnot [array]) { $events = @($events) }
        
        foreach ($evt in $events) {
            if ($typeEventCount -ge $maxEventsPerType) { break }
            
            # Map to OfficeActivity-like schema
            $logEntry = @{
                TimeGenerated     = if ($evt.CreationTime) { $evt.CreationTime } else { [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") }
                OfficeWorkload    = if ($evt.Workload) { $evt.Workload } else { $contentType }
                Operation         = $evt.Operation
                ResultStatus      = $evt.ResultStatus
                UserId            = $evt.UserId
                UserKey           = $evt.UserKey
                UserType          = $evt.UserType
                ClientIP          = $evt.ClientIP
                ObjectId          = $evt.ObjectId
                OrganizationId    = $evt.OrganizationId
                RecordType        = $evt.RecordType
                Workload          = $evt.Workload
                ContentType       = $contentType
                # Flatten frequently used fields
                SourceFileName    = $evt.SourceFileName
                SourceFileExtension = $evt.SourceFileExtension
                SiteUrl           = $evt.SiteUrl
                SourceRelativeUrl = $evt.SourceRelativeUrl
                ItemType          = $evt.ItemType
                EventSource       = $evt.EventSource
                # Store full event as JSON for forensics
                RawEventData      = ($evt | ConvertTo-Json -Depth 5 -Compress)
            }
            
            $batchBuffer += $logEntry
            $typeEventCount++
            
            # Send batch when buffer is full
            if ($batchBuffer.Count -ge $batchSize) {
                $success = Send-ToLogAnalytics -WorkspaceId $workspaceId -SharedKey $WorkspaceSharedKey -LogType $logType -LogEntries $batchBuffer
                if ($success) {
                    $totalBatchesSent++
                    Write-Output "    Batch $totalBatchesSent sent ($($batchBuffer.Count) events)"
                } else {
                    Write-Warning "    Batch $totalBatchesSent FAILED"
                }
                $batchBuffer = @()
            }
        }
    }
    
    # Send remaining events in buffer
    if ($batchBuffer.Count -gt 0) {
        $success = Send-ToLogAnalytics -WorkspaceId $workspaceId -SharedKey $WorkspaceSharedKey -LogType $logType -LogEntries $batchBuffer
        if ($success) {
            $totalBatchesSent++
            Write-Output "    Final batch sent ($($batchBuffer.Count) events)"
        } else {
            Write-Warning "    Final batch FAILED"
        }
        $batchBuffer = @()
    }
    
    Write-Output "    ${contentType}: $typeEventCount events from $blobsProcessed blobs"
    $totalEventsCollected += $typeEventCount
}

# ============================================================
# 6. Update Last Poll Time
# ============================================================
Write-Output "`n[Step 5] Updating state..."

if ($failedTypes.Count -eq 0 -or $totalEventsCollected -gt 0) {
    try {
        Set-AutomationVariable -Name "M365LastPollTime" -Value $endTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        Write-Output "  Last poll time updated to: $($endTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    } catch {
        Write-Warning "  Failed to update M365LastPollTime variable: $($_.Exception.Message)"
        Write-Output "  Create it manually: New-AzAutomationVariable -Name 'M365LastPollTime' -Value '$($endTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))' -Encrypted `$false"
    }
} else {
    Write-Warning "  All content types failed, NOT updating last poll time"
}

# ============================================================
# 7. Summary
# ============================================================
Write-Output "`n============================================"
Write-Output "  M365 Activity Log Collection Summary"
Write-Output "============================================"
Write-Output "  Time window : $startStr → $endStr"
Write-Output "  Content types polled : $($typeList.Count)"
Write-Output "  Total events collected: $totalEventsCollected"
Write-Output "  Total batches sent    : $totalBatchesSent"
Write-Output "  Target table          : ${logType}_CL"
if ($failedTypes.Count -gt 0) {
    Write-Output "  Failed types          : $($failedTypes -join ', ')"
}
Write-Output "============================================"
Write-Output "[Done] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
