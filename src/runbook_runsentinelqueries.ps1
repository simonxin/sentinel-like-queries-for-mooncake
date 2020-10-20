<#
    .DESCRIPTION
        An example runbook which is used to run the sentinel query imported
#>


param (
[Parameter(Mandatory=$false)][string]$cloud="mooncake",
[Parameter(Mandatory=$false)][string]$logType="sentinelscanreport",
[Parameter(Mandatory=$true)][string]$querytype,
[Parameter(Mandatory=$true)][string]$workspacename,
[Parameter(Mandatory=$true)][string]$resourcegroupname
      )

Import-Module Az.Accounts
Import-Module Az.OperationalInsights

<#
    .DESCRIPTION
        Invokes a query against the Log Analtyics Query API.

    .EXAMPLE
        Invoke-LogAnaltyicsQuery -WorkspaceName my-workspace -SubscriptionId 0f991b9d-ab0e-4827-9cc7-984d7319017d -ResourceGroup my-resourcegroup
            -Query "union * | limit 1" -CreateObjectView

    .PARAMETER WorkspaceName
        The name of the Workspace to query against.

    .PARAMETER SubscriptionId
        The ID of the Subscription this Workspace belongs to.

    .PARAMETER ResourceGroup
        The name of the Resource Group this Workspace belongs to.

    .PARAMETER Query
        The query to execute.
    
    .PARAMETER Timespan
        The timespan to execute the query against. This should be an ISO 8601 timespan.

    .PARAMETER IncludeTabularView
        If specified, the raw tabular view from the API will be included in the response.

    .PARAMETER IncludeStatistics
        If specified, query statistics will be included in the response.

    .PARAMETER IncludeRender
        If specified, rendering statistics will be included (useful when querying metrics).

    .PARAMETER ServerTimeout
        Specifies the amount of time (in seconds) for the server to wait while executing the query.

    .PARAMETER Environment
        Internal use only.
#>
function Invoke-LogAnalyticsQuery {
param(
    [string]
    [Parameter(Mandatory=$true)]
    $WorkspaceName,

    [guid]
    [Parameter(Mandatory=$true)]
    $SubscriptionId,

    [string]
    [Parameter(Mandatory=$true)]
    $ResourceGroup,

    [string]
    $Query,

    [string]
    [Parameter(Mandatory=$true)]    
    [ValidateSet("query", "metadata","sharedKeys","workspace")]
    $querytype,

    [string]
    $Timespan,

    [switch]
    $IncludeTabularView,

    [switch]
    $IncludeStatistics,

    [switch]
    $IncludeRender,

    [int]
    $ServerTimeout,

    [string]
    [ValidateSet("", "int", "aimon","mooncake")]
    $Environment = ""

    )

    $ErrorActionPreference = "Stop"

    $accessToken = GetAccessToken

    $armhost = GetArmHost $environment

    if ($null -eq $ServerTimeout) {
        $ServerTimeout = 300
    }

    try {
        
        if ($querytype -eq "query") {
            $queryParams = @("api-version=$queryapiversion")
            $queryParamString = [string]::Join("&", $queryParams)        
            $uri = BuildUri $armHost $subscriptionId $resourceGroup $workspaceName $queryParamString $querytype
    
            $body = @{
                "query" = $query;
                "timespan" = $Timespan
            } | ConvertTo-Json
        
            $headers = GetHeaders $accessToken -IncludeStatistics:$IncludeStatistics -IncludeRender:$IncludeRender -ServerTimeout $ServerTimeout
        
            $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Body $body -ContentType "application/json" -Headers $headers -Method Post -ErrorAction:Ignore
            
        } elseif ($querytype -eq "metadata") {
            $queryParams=@("api-version=$metadataapiVersion")
            $uri = BuildUri $armHost $subscriptionId $resourceGroup $workspaceName $queryParams $querytype
            $headers = GetHeaders $accessToken -IncludeStatistics:$IncludeStatistics -IncludeRender:$IncludeRender -ServerTimeout $ServerTimeout
            $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers $headers -Method Post -ErrorAction:Ignore
                
        } elseif ($querytype -eq "sharedKeys") {
    
            $queryParams=@("api-version=$queryapiVersion")
            $uri = BuildUri $armHost $subscriptionId $resourceGroup $workspaceName $queryParams $querytype
            $headers = GetHeaders $accessToken -IncludeStatistics:$IncludeStatistics -IncludeRender:$IncludeRender -ServerTimeout $ServerTimeout
            $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers $headers -Method Post -ErrorAction:Ignore
        } elseif ($querytype -eq "workspace") {
            $queryParams=@("api-version=2020-08-01")
            $uri = BuildUri $armHost $subscriptionId $resourceGroup $workspaceName $queryParams $querytype
            $headers = GetHeaders $accessToken -IncludeStatistics:$IncludeStatistics -IncludeRender:$IncludeRender -ServerTimeout $ServerTimeout
            $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers $headers -Method Get -ErrorAction:Ignore
         }

        if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
            $statusCode = $response.StatusCode
            $reasonPhrase = $response.StatusDescription
            $message = $response.Content
            throw "Failed to execute query.`nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
        } 
    
    
        $data = $response.Content | ConvertFrom-Json
    

        $result = New-Object PSObject
        $result | Add-Member -MemberType NoteProperty -Name Response -Value $response
    
        # In this case, we only need the response member set and we can bail out
        if ($response.StatusCode -eq 204) {
            $result
            return
        }
        $objectView = CreateObjectView  $data -querytype $querytype

        $result | Add-Member -MemberType NoteProperty -Name Results -Value $objectView
    
        if ($IncludeTabularView) {
            $result | Add-Member -MemberType NoteProperty -Name Tables -Value $data.tables
        }
    
        if ($IncludeStatistics) {
            $result | Add-Member -MemberType NoteProperty -Name Statistics -Value $data.statistics
        }
    
        if ($IncludeRender) {
            $result | Add-Member -MemberType NoteProperty -Name Render -Value $data.render
        }        

    }
    catch {
        # return null if invoke query is failed
        $result = ""
    }
   
    $result
}

function GetAccessToken {
    $azureCmdlet = get-command -Name Get-AzureRMContext -ErrorAction SilentlyContinue
    if ($azureCmdlet -eq $null)
    {
        $null = Import-Module Az.Accounts -ErrorAction Stop;
    }
    $AzureContext = & "Get-AzContext" -ErrorAction Stop;
    $authenticationFactory = New-Object -TypeName Microsoft.Azure.Commands.Common.Authentication.Factories.AuthenticationFactory
    if ((Get-Variable -Name PSEdition -ErrorAction Ignore) -and ('Core' -eq $PSEdition)) {
        [Action[string]]$stringAction = {param($s)}
        $serviceCredentials = $authenticationFactory.GetServiceClientCredentials($AzureContext, $stringAction)
    } else {
        $serviceCredentials = $authenticationFactory.GetServiceClientCredentials($AzureContext)
    }

    # We can't get a token directly from the service credentials. Instead, we need to make a dummy message which we will ask
    # the serviceCredentials to add an auth token to, then we can take the token from this message.
    $message = New-Object System.Net.Http.HttpRequestMessage -ArgumentList @([System.Net.Http.HttpMethod]::Get, "http://foobar/")
    $cancellationToken = New-Object System.Threading.CancellationToken
    $null = $serviceCredentials.ProcessHttpRequestAsync($message, $cancellationToken).GetAwaiter().GetResult()
    $accessToken = $message.Headers.GetValues("Authorization").Split(" ")[1] # This comes out in the form "Bearer <token>"

    $accessToken
}

function GetArmHost {
param(
    [string]
    $environment
    )

    switch ($environment) {
        "" {
            $armHost = "management.azure.com"
        }
        "mooncake" {
            $armHost = "management.chinacloudapi.cn"
        }
        "int" {
            $armHost = "api-dogfood.resources.windows-int.net"
        }
    }

    $armHost
}

function BuildUri {
param(
    [string]
    $armHost,
    
    [string]
    $subscriptionId,

    [string]
    $resourceGroup,

    [string]
    $workspaceName,

    [string]
    $queryParamString,

    [string]
    [ValidateSet("query", "metadata","sharedKeys","workspace")]
    $querytype
    )

    if ($querytype -eq 'query') { 
    
      "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
        "microsoft.operationalinsights/workspaces/$workspaceName/api/query?$queryParamString"
    } elseif ($querytype -eq 'metadata') {
    "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
        "microsoft.operationalinsights/workspaces/$workspaceName/metadata?$queryParamString"

    } elseif ($querytype -eq 'sharedKeys') {
        "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
        "microsoft.operationalinsights/workspaces/$workspaceName/sharedKeys?$queryParamString"

    } elseif($querytype -eq 'workspace') {
        "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
        "microsoft.operationalinsights/workspaces/$workspaceName"+"?"+$queryParamString
    }
}

function GetHeaders {
param(
    [string]
    $AccessToken,

    [switch]
    $IncludeStatistics,

    [switch]
    $IncludeRender,

    [int]
    $ServerTimeout
    )

    $preferString = "response-v1=true"

    if ($IncludeStatistics) {
        $preferString += ",include-statistics=true"
    }

    if ($IncludeRender) {
        $preferString += ",include-render=true"
    }

    if ($ServerTimeout -ne $null) {
        $preferString += ",wait=$ServerTimeout"
    }

    $headers = @{
        "Authorization" = "Bearer $accessToken";
        "prefer" = $preferString;
        "x-ms-app" = "LogAnalyticsQuery.psm1";
        "x-ms-client-request-id" = [Guid]::NewGuid().ToString();
    }

    $headers
}

function CreateObjectView {
param(
    $data,
    [string]
    [ValidateSet("query", "metadata","sharedKeys","workspace")]
    $querytype    
    )

    if($querytype -eq "query") {
    # Find the number of entries we'll need in this array
        $count = 0
        foreach ($table in $data.Tables) {
            $count += $table.Rows.Count
        }

        $objectView = New-Object object[] $count
        $i = 0;
        foreach ($table in $data.Tables) {
            foreach ($row in $table.Rows) {
            # Create a dictionary of properties
            $properties = @{}
            for ($columnNum=0; $columnNum -lt $table.Columns.Count; $columnNum++) {
                $properties[$table.Columns[$columnNum].name] = $row[$columnNum]
            }
            # Then create a PSObject from it. This seems to be *much* faster than using Add-Member
            $objectView[$i] = (New-Object PSObject -Property $properties)
            $null = $i++
            }
        }

       
    } elseif ($querytype -eq "metadata") {
        # for metadaa, return the table name and column names only
        $count = $data.Tables.count
        $objectView = New-Object object[] $count
        $i = 0;
        foreach ($table in $data.tables) {
            $properties = @{
                datatype = $table.name
                columns = $table.columns
            }
            $objectView[$i] = (New-Object PSObject -Property $properties)
            $null = $i++
        }
    } else {

        $objectView = $data
    }

    $objectView
}



# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}


# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.cn" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}





$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName

    "Logging in to Azure..."
    Add-AzAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint `
        -EnvironmentName AzureChinaCloud
 }
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}


$metadataapiVersion = "2017-10-01"
$queryapiversion = "2020-03-01-preview"
$TimeStampField = ""
$subscriptionId = $servicePrincipalConnection.SubscriptionId

# filter on query type
# $querytype = "Sentinel-Insight-Hunting" 
# $querytype = "Sentinel-Insight-Detection"
$logdetails = $FALSE

$savedsearches = $(get-AzOperationalInsightsSavedSearch -resourcegroupname $resourcegroupname -workspacename $workspacename).value


foreach ($search in $savedsearches ) {
    if($search.properties.Category.contains($querytype)) {
        if ($search.properties.query.contains("TimeGenerated")){
            #test
        } elseif ($search.properties.query.contains("timestamp")) {
            #test
        } else {
            write-host $search.properties.query
            write-host $search.properties.displayname
            write-host $search.properties.Category
        }

    } 

}

$queryresult = @()
$querydetails = @()

# get table schema if required
# $tableindex = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspacename -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -querytype "metadata").Results

foreach ($search in $savedsearches ) {

        if($search.properties.Category.contains($querytype)) {
            if ($querytype -eq "Sentinel-Insight-Detection") {
                $severity = $search.properties.Category.split('-')[3]
            } else {
                $severity = "none"
            }

            $query = $($search.properties.query -split '//\n')[-1]
            $query = $query.trim()
            
            $result = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspacename -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -Query $query -querytype "query").Results 
            
            if ($NLLL -ne $result) {
     
                    $queryresult += [PSCustomObject]@{
                        Category = $search.properties.Category
                        rulename = $search.properties.displayname
                        type = $querytype
                        query = $query
                        severity = $severity
                        count = $result.count
                   }
                
               if ($logdetails ) {
                    foreach ($resultojb in $result) {
                        $querydetails += [PSCustomObject]@{
                            Category = $search.properties.Category
                            rulename = $search.properties.displayname
                            type = $querytype
                            severity = $severity
                            details = $resultojb
                        }
                    }
               }
           
            }
        }
}



$jsonTable = ConvertTo-Json -InputObject $queryresult
$jsonTable  = $jsonTable.Replace("null", 0)

$workspace = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspacename -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -querytype "workspace").response | ConvertFrom-Json
$sharedkeys = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspacename -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -querytype "sharedkeys").response | ConvertFrom-Json
$queryresult

# upload the result
Post-LogAnalyticsData -customerId $workspace.properties.customerId -sharedKey $sharedkeys.primarySharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsonTable)) -logType $logType  

