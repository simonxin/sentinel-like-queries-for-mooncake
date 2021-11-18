<#
    .DESCRIPTION
        An example powershell module to get and update query pack 
#>


Import-Module Az.Accounts


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
        
            $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Body $body -ContentType "application/json; charset=utf-8" -Headers $headers -Method Post -ErrorAction:Ignore
            
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
    $ruleId="",

    [string]
    $apiversion = "2019-09-01-preview"

    )

    if ("" -ne $ruleId) {
        
        "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
        "Microsoft.OperationalInsights/queryPacks/$querypackname/queries/$ruleId"+"?"+"api-version=$apiversion"
    } else {
        "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
        "Microsoft.OperationalInsights/queryPacks/$querypackname/queries"+"?"+"api-version=$apiversion"
    }   
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
    
    


function get-savedqueries {
    param(
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$environment,
    
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$subscriptionId,

     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$querypackname,
     
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$resourceGroup,
      
     [parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true)]
     [array]$registeredruletype=@(),
    
     [parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true)]
     [string]$ruletype="",
    
     [parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true)]
     [string]$ruleId="",

     [parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true)]
     [string]$rulename=""

    )
    
    $armhost = GetArmHost $environment

    $accessToken = GetAccessToken
    $headers = GetHeaders -AccessToken $accessToken

    if ($NULL -ne $ruleId) {
        $uri = BuildquerypackUri -armHost $armHost -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -ruleId $ruleId
    } else {
        $uri = BuildquerypackUri -armHost $armHost -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname
    }

  
    $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -ContentType "application/json; charset=utf-8" -Headers $headers -Method Get -ErrorAction:Ignore
            
    if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
        $statusCode = $response.StatusCode
        $reasonPhrase = $response.StatusDescription
        $message = $response.Content
        throw "Failed to execute query.`nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
    } 
    
    
    $data = $response.Content | ConvertFrom-Json 

    # return exact rule if rule ID is provided
    if ("" -ne $ruleId) {
        $securityrules = $data.value
    } else {
    
        if ($registeredruletype.length -gt 0) {
            $securityrules = $data.value | where {$_.properties.properties.category -in $registeredruletype}
        } else {
            $securityrules = $data.value
        }

        if ("" -ne $rulename) {
            $securityrules = $securityrules | where {$_.properties.displayName -like $rulename}
        } elseif ("" -ne $ruletype) {
            # if ruletype is not NULL
            $securityrules = $securityrules | where {$_.properties.properties.type -like $ruletype}
        } 
   }

    $securityrules
}


# updated existing query pack rules
function update-savedqueries {
    param(
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$environment,
    
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$subscriptionId,

     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$querypackname,
     
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$resourceGroup,
      
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$ruleId,

     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [object]$properties

    )
    
    
    $armhost = GetArmHost $environment

    $accessToken = GetAccessToken
    $headers = GetHeaders -AccessToken $accessToken
    $uri = BuildquerypackUri -armHost $armHost -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -ruleId $ruleId

    # remove id if it exists
    $properties.PSObject.properties.Remove('id')
    $object = [PSCustomObject]@{
        properties = $properties
    }
    $body = $object | convertto-json -depth 10
      
    $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -ContentType "application/json;charset=utf-8" -Headers $headers -Body $body -Method PUT -ErrorAction:Ignore
            
    if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
        $statusCode = $response.StatusCode
        $reasonPhrase = $response.StatusDescription
        $message = $response.Content
        throw "Failed to execute query.`nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
    } else {

        $response.Content
    }
    
    
}


# export saved query to CSV

function export-savedqueries {
    param(
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$environment,
    
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$subscriptionId,

     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$querypackname,
     
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$resourceGroup,

     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$exportpath
      
    )
    
    $armhost = GetArmHost $environment

    $accessToken = GetAccessToken
    $headers = GetHeaders -AccessToken $accessToken

    $uri = BuildquerypackUri -armHost $armHost -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname
      
    $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -ContentType "application/json; charset=utf-8" -Headers $headers -Method Get -ErrorAction:Ignore
            
    if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
        $statusCode = $response.StatusCode
        $reasonPhrase = $response.StatusDescription
        $message = $response.Content
        throw "Failed to execute query.`nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
    } 
    
    
    $data = $response.Content | ConvertFrom-Json 
    $securityrules = $data.value

    # return exact rule if rule ID is provided
    $rulelist = @()
    foreach ($rule in $securityrules) {

        if ($rule.properties.properties.type -eq 'Detection') {
            $rulelist += [PSCustomObject]@{
                ruleId = $rule.properties.id
                displayName = $rule.properties.displayName                
                enabled = $rule.properties.properties.enabled
                type = $rule.properties.properties.type
                severity = $rule.properties.properties.severity
                category = $rule.properties.properties.category
                source = $rule.properties.properties.source
                queryFrequency = $rule.properties.properties.queryFrequency
                queryPeriod = $rule.properties.properties.queryPeriod
                description = $rule.properties.description
                body = $rule.properties.body
            }
        } else {
            $rulelist += [PSCustomObject]@{
                ruleId = $rule.properties.id
                displayName = $rule.properties.displayName
                enabled = $rule.properties.properties.enabled
                type = $rule.properties.properties.type
                severity = 'none'
                category = $rule.properties.properties.category
                source = $rule.properties.properties.source
                queryFrequency = 'none'
                queryPeriod = 'none'
                description = $rule.properties.description
                body = $rule.properties.body
            }

        }

    }

    # use utf+8 to support chinese in rule description
    try {
        $rulelist | export-csv -encoding UTF8 -Path $exportpath -NoTypeInformation -force
        write-host "saved queries are exported to $exportpath"
    } catch {
        write-error "failed to export saved queries to $exportpath"
    }
    
}



# import queries from an CSV file to query pack

function import-savedqueries {
    param(
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$environment,
    
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$subscriptionId,

     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$querypackname,
     
     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$resourceGroup,

     [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
     [string]$sourcefile
      
    )
    
    # make a backup of oringal file
    $backupfile = $sourcefile+"_bak"
    copy-item -path $sourcefile -Destination $backupfile -force  

    # load the source file
    If (test-path $sourcefile) {
        $securityrules = import-csv $sourcefile

        $related = [PSCustomObject]@{
            categories = @('security')
            resourceTypes = @('microsoft.operationalinsights/workspaces')
        }

        foreach ($securityrule in  $securityrules){

            $displayname = $securityrule.displayName
          
            # loop each rule and comparing with properties. If changed, update the query pack with new rule property

            $existingrule = get-savedqueries -environment $environment -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -rulename $displayname
           
            # if rule existing
            if ($existingrule) {
                $ruleId = $existingrule.Name
                if ($ruleId -ne  $securityrule.ruleId) {
                    write-warning "conflict ruleID existing for rule: $displayname. skip the rule update"
                    continue
                }
                
            } else {
                $ruleId = $([guid]::NewGuid()).guid.tostring()
            }
            
            $doupdate = $false

            if ($securityrule.type -eq 'Detection') {

                if (($existingrule.properties.properties.enabled -notlike $securityrule.enabled) `
                    -or ($existingrule.properties.properties.type -notlike $securityrule.type) `
                    -or ($existingrule.properties.properties.severity -notlike $securityrule.severity) `
                    -or ($existingrule.properties.properties.category -notlike $securityrule.category) `
                    -or ($existingrule.properties.properties.source -notlike $securityrule.source) `
                    -or ($existingrule.properties.properties.queryFrequency -notlike $securityrule.queryFrequency) `
                    -or ($existingrule.properties.properties.queryPeriod -notlike $securityrule.queryPeriod) `
                ) {
                    $doupdate = $true
                    write-host "detect property changes on rule: $displayname"
                   }

                   $ruleproperty = [PSCustomObject]@{
                    enabled = $securityrule.enabled
                    type = $securityrule.type
                    severity = $securityrule.severity
                    category = $securityrule.category
                    source = $securityrule.source
                    queryFrequency = $securityrule.queryFrequency
                    queryPeriod = $securityrule.queryPeriod
                  }

            } else {

                if (($existingrule.properties.properties.enabled -notlike $securityrule.enabled) `
                -or ($existingrule.properties.properties.type -notlike $securityrule.type) `
                -or ($existingrule.properties.properties.category -notlike $securityrule.category) `
                -or ($existingrule.properties.properties.source -notlike $securityrule.source) `
                ) {
                    $doupdate = $true
                    write-host "detect property changes on rule: $displayname"   
                }

                $ruleproperty = [PSCustomObject]@{
                    enabled = $securityrule.enabled
                    type = $securityrule.type
                    category = $securityrule.category
                    source = $securityrule.source
                }

            }

            if ( $existingrule.properties.body.compareto($securityrule.body) -ne 0) {
                write-host "detect query body changes on rule: $displayname"
                $doupdate = $true
            }


            if ( $existingrule.properties.description.compareto($securityrule.description) -ne 0) {
                write-host "detect rule description changes on rule: $displayname"
                $doupdate = $true
            }

            if ($doupdate) {
    
                $properties = [PSCustomObject]@{
                    displayName =  $displayname
                    description =  $securityrule.description
                    body =  $securityrule.body
                    related = $related
                    properties = $ruleproperty
                }

                write-host "update rule: $displayname"
                update-savedqueries -environment $environment -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -ruleid $ruleid -properties $properties
            }

        }

    } else {
        Write-Warning "$sourcefile is not found"

    }

}



       
# $securityrules = get-savedqueries -environment $cloud -subscriptionId $subscriptionId -resourceGroup $resourcegroupname -querypackname $querypackname -registeredruletype $registeredruletype -querytype $querytype

