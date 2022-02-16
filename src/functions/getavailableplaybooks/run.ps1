using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

# request MSI token
$resourceURI = "https://vault.azure.cn"
$tokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
$tokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $tokenAuthURI
$accessToken = $tokenResponse.access_token


# Interact with query parameters or the body of the request.
$alertid = $Request.Query.alertid

$alertworkflow = $Request.Query.alertworkflow

if (-not $alertid) {
    $alertid = $Request.Body.alertid
}

if (-not $alertworkflow) {
    $alertworkflow = $Request.Body.alertworkflow
}


$body = "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."

if ($alertid -and $alertworkflow) {
    $body = "start workflow $alertworkflow for security alert $alertid"
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $tokenAuthURI + $accessToken 
})



