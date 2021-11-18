<#
    .DESCRIPTION
        An example runbook which is used to run the sentinel query imported
#>


param (
[Parameter(Mandatory=$false)][string]$cloud="mooncake",
[Parameter(Mandatory=$false)][string]$logType="sentinelscanreport",
[Parameter(Mandatory=$true)][string]$workspacename,
[Parameter(Mandatory=$true)][string]$resourcegroupname,
#[Parameter(Mandatory=$false)][array]$registeredruletype=["AzureActivity","AzureActiveDirectory","Syslog","Heartbeat","SecurityEvents","AzureSecurityCenter","WAF","Network","HIDS","DSM","honeypot"],
[Parameter(Mandatory=$false)][array]$registeredruletype=@(),
[Parameter(Mandatory=$false)][string]$querypackname="sentinel-like-security-queries",
[Parameter(Mandatory=$false)][array]$noisyrules = @()
)

# load required azure module 

Import-Module Az.Accounts


# load required variable. if the variable is 360 or it is initial time: 0:00, reset to 0

$currentcount = [int]$(Get-AutomationVariable -Name 'executioncount')

$currentcount = $currentcount+1

"execution: $currentcount"
if ($currentcount -gt 0) {
    $currenttime = (Get-Date).ToUniversalTime()
    $initialtime = [Datetime]::ParseExact([string]$(Get-AutomationVariable -Name 'initialtime'), 'HH:mm', $null)
    $diff= [int]$(New-TimeSpan -Start $currenttime -End $initialtime).TotalMinutes
    if ($diff -lt 0) {
        $diff = -1*$diff
    } 
    if (($diff -le 5) -or ($diff -ge 1435)) {
        "reset executioncount variable"
        $currentcount = 0
    }
}
Set-AutomationVariable -Name 'executioncount' -Value $currentcount

# define iniial PID to record the generated alert as a uniqual ID
$PIDHeader = (Get-Date).ToString("yyyyMMddhhmm")
$PIDindex = 1

$detaillogType = $logType+"details"


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
    [Parameter(Mandatory=$false)] 
    $Timespan='P1D',

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
            # map to mooncake logA rest API endpoint
            $accessToken = (Get-AzAccessToken -ResourceUrl "https://api.loganalytics.azure.cn/").token
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

function BuildquerypackUri {
param(
    [string]
    $armHost,
    
    [string]
    $subscriptionId,

    [string]
    $resourceGroup,

    [string]
    $querypackname,

    [string]
    $apiversion = "2019-09-01-preview"

    )


    "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
        "Microsoft.OperationalInsights/queryPacks/$querypackname/queries?api-version=$apiversion"
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
        
          "https://api.loganalytics.azure.cn/v1/workspaces/$workspaceName/query"
    
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

function GetHeaders {
    param(
        [string]
        $AccessToken,
    
        [switch]
        $IncludeStatistics,
    
        [string]
        $headerapp='LogAnalyticsQuery.ps1',

        [string]
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
    
        if ($null -eq $headerapp) {
            $headerapp = 'LogAnalyticsQuery.ps1'
        }
    
        $headers = @{
            "Authorization" = "Bearer $accessToken";
            "prefer" = $preferString;
            "x-ms-app" = $headerapp;
            "x-ms-client-request-id" = [Guid]::NewGuid().ToString();
        }
    
        $headers
    }


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
    

# functions to dump the exact query interval
    
function Getexecutioninterval {
    param(
        [string]
        $queryFrequency
        )

        try{ $executionint = [int]$queryFrequency.Substring(0,$queryFrequency.Length-1) 
        } catch {
            $executionint = 1
        }

        $executionstr = $queryFrequency.Substring($queryFrequency.Length-1,1)
        if ($executionstr -like 'd') {
            $executionx = 1440
        } elseif($executionstr -like 'h') {
            $executionx = 60
        } else {
            $executionx = 1
        }
    
        $executionminutes = $executionint*$executionx
        # limit to minimal 10 minutes, if the interval larger than 10, set the interval to 10x
        if ($executionminutes -lt 10) {
            $executioncount  = 1
        } else {
            $executioncount = [int]($executionminutes/10)
        }

        return $executioncount

    }


    
# functions to build a valid ISO8601 time period string. Support to D and TM only
# https://en.wikipedia.org/wiki/ISO_8601
    
function buildtimespan {
    param(
        [string]
        $queryPeriod
        )

        try{ $periondnum = [int]$queryPeriod.Substring(0,$queryPeriod.Length-1) 
        } catch {
            $periondnum = 1
        }
        $executionstr = $queryPeriod.Substring($queryPeriod.Length-1,1)
        if ($executionstr -like 'm') {
            $periondheader = 'PT'
            $periondend = 'M'
            $minnum = 10
            $maxnum = 1440
        } elseif($executionstr -like 'h') {
            $periondheader = 'PT'
            $periondend = 'H'
            $minnum = 1
            $maxnum = 24
        } else {
            $periondheader = 'P'
            $periondend = 'D'
            $minnum = 1
            $maxnum = 30
        }
    
        # convert to min/max periond 
        if ($periondnum -lt $minnum) {
            $periondnum  = $minnum
        } elseif($periondnum -gt $maxnum) {
            $periondnum  = $maxnum
        }

        $timespan = $periondheader+[string]$periondnum+$periondend

        return $timespan

    }


# functions to load queries
function get-savedqueries {
    param(
     [string]
     $environment,
    
     [string]
     $subscriptionId,

     [string]
     $querypackname,
     
     [string]
     $resourceGroup,
      
     [array]
     $registeredruletype=@(),
      
     [string]
     $apiversion = "2019-09-01-preview"
        
    )
    
    $armhost = GetArmHost $environment

    $accessToken = GetAccessToken
    $headers = GetHeaders -AccessToken $accessToken

    $uri = BuildquerypackUri $armHost $subscriptionId $resourcegroup $querypackname

    $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -ContentType "application/json" -Headers $headers -Method Get -ErrorAction:Ignore
            
    if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
        $statusCode = $response.StatusCode
        $reasonPhrase = $response.StatusDescription
        $message = $response.Content
        throw "Failed to execute query.`nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
    } 
    
    
    $data = $response.Content | ConvertFrom-Json 

    if (($registeredruletype | measure-object).count -gt 0) {
        $securityrules = $data.value | where {$_.properties.properties.category -in $registeredruletype}
    } else {
        $securityrules = $data.value
    }    

    $securityrules

}
        



$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName

    "Logging in to Azure..."
    Connect-AzAccount `
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
set-azcontext $subscriptionId

       
$securityrules = get-savedqueries -environment $cloud -subscriptionId $subscriptionId -resourceGroup $resourcegroupname -querypackname $querypackname -registeredruletype $registeredruletype


$workspace = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspacename -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -querytype "workspace").response | ConvertFrom-Json
$sharedkeys = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspacename -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -querytype "sharedkeys").response | ConvertFrom-Json


$queryresult = @()
$queryresultdetails = @()

foreach ($securityrule in $securityrules ) {

# disable least common processes execution as it it noisy
    
        if (($securityrule.properties.displayname -notin $noisyrules) -and $securityrule.properties.properties.enabled) {
            # "process $querytype rule: $($securityrule.properties.DisplayName)"
            
            $query = $securityrule.properties.body
            $queryname = $securityrule.properties.displayName
            $query = $query.trim()
            $queryFrequency = $securityrule.properties.properties.queryFrequency
            $queryPeriod = $securityrule.properties.properties.queryPeriod

            # set default interval to 1 hour and default log query period to 1d if not set
            if ($NULL -eq $queryFrequency ) {
                $queryFrequency = '1h'
            }

            if ($NULL -eq $queryPeriod ) {
                $queryPeriod = '1d'
            }
            
            $executioncount = Getexecutioninterval $queryFrequency
            $timespan = buildtimespan  $queryPeriod
            
            if([int]$currentcount%$executioncount -eq 0) {
                $shouldrun = $true 
            } else {
                $shouldrun = $false
            }

            # determine if the rule is triggered to run at this time. 
            # only run detection rule. hunting rules should be run on-demand

            if (($securityrule.properties.properties.type -like 'Detection') -and $shouldrun) {
                "rule is triggered: $queryname"
                $result = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspace.properties.customerId -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -Query $query -Timespan $timespan -querytype "query").Results 
            } else {
                $result = $NULL
            }



            if ($NLLL -ne $result) {

                    $count = ($result | measure-object).count
                    $PIDstr = $PIDHeader + "#" + $PIDindex.tostring().padleft(3,'0')
                    "returned records: $count"
                    $queryresult += [PSCustomObject]@{
                        Category = $securityrule.properties.properties.Category
                        rulename = $securityrule.properties.displayname
                        description = $securityrule.properties.description
                        type = $securityrule.properties.properties.type
                        query = $query
                        severity = $securityrule.properties.properties.severity
                        count = $count
                        timespan = $timespan
                        pid = $PIDstr
                   }

                    foreach ($resultobj in $result) {
                        $queryresultdetails += [PSCustomObject]@{
                            pid = $PIDstr
                            details = $resultobj | convertto-json -depth 10
                        }
                    }
                    $PIDindex = $PIDindex+1                  
               
                
            } else {
                # record query statement per 8 hours even it is not triggered
                if([int]$currentcount%48 -eq 0) {
                    "log query statement only for rule:  $queryname"
                    $queryresult += [PSCustomObject]@{
                        Category = $securityrule.properties.properties.Category
                        rulename = $securityrule.properties.displayname
                        description = $securityrule.properties.description
                        type = $securityrule.properties.properties.type
                        query = $query
                        severity = $securityrule.properties.properties.severity
                        count = 0
                        timespan = $timespan
                   }
                }
            }

            
        }
}



$jsonTable = ConvertTo-Json -InputObject $queryresult
# upload the result
Post-LogAnalyticsData -customerId $workspace.properties.customerId -sharedKey $sharedkeys.primarySharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsonTable)) -logType $logType

$jsonTable = ConvertTo-Json -InputObject $queryresultdetails
# upload the result details
Post-LogAnalyticsData -customerId $workspace.properties.customerId -sharedKey $sharedkeys.primarySharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsonTable)) -logType $detaillogType
