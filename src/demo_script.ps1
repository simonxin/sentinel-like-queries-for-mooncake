
$exportfile = "c:\case\test.csv"
$sourcefile = "c:\case\test.csv"
# $registeredruletype = @('Linux')

import-module ./securityruletoolkit.ps1 -force
$environment = "Mooncake"
$subscriptionId = "0f2daa80-6b16-44ee-8016-4ad888e059ac"

$resourcegroup = "omsdemo"
$querypackname = "sentinel-like-security-queries"

$rulename = 'SSH - Potential Brute Force'


export-savedqueries -environment $environment -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -exportpath $exportfile


import-savedqueries -environment $environment -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -sourcefile $sourcefile


$securityrule = get-savedqueries -environment $environment -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -rulename $rulename

$ruleId = $securityrule.Name

# for exampe:
# update the rule severity from Low to High
$securityrule.properties.properties.severity = 'Low'
$securityrule.properties.properties.queryFrequency = '1h'
$securityrule.properties.properties.queryPeriod = '1h'
$properties = $securityrule.properties


update-savedqueries -environment $environment -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -ruleid $ruleid -properties $properties


#IPCustomEntity = IPAddress, AccountCustomEntity 
#HostCustomEntity
#ResourceId
#SubscriptionId



$workspace = "somsdemoworkshop"
$workspaceresourcegroup = "omsdemo"
$automationaccount = "somsauto"
$auaccountresourcegroup = "omsdemo"

$templatefile = "C:\GitHub\sentinel-like-queries-for-mooncake\template\securityworkflows.json"
$recipientAddress = "simonxin@live.com"

# Define parameters
$params = @{
    workspacename = $workspace
    workspaceresourcegroup = $workspaceresourcegroup
    auaccountname = $automationaccount
    auaccountresourcegroup = $auaccountresourcegroup
    recipientAddress = $recipientAddress
}


# do group deployment
New-AzResourceGroupDeployment -ResourceGroupName $workspaceresourcegroup -Name "securityworkflows" `
-TemplateFile $templatefile `
-TemplateParameterObject $params `
-verbose



$properties = [PSCustomObject]@{
    displayName =  $displayname
    description =  $securityrule.description
    body =  $securityrule.body
    related = $related
    properties = $ruleproperty
}

write-host "update rule: $displayname"
update-savedqueries -environment $environment -subscriptionId $subscriptionId -resourceGroup $resourcegroup -querypackname $querypackname -ruleid $ruleid -properties $properties