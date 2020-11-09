# Introduction
Microsoft Azure Sentinel is a scalable, cloud-native, security information event management (SIEM) and security orchestration automated response (SOAR) solution. 
For more information about Azure Sentinel, you can go to the below link: 
https://azure.microsoft.com/en-us/resources/videos/introducing-microsoft-azure-sentinel/

 To allow customers to leverage the security experience in Azure China Cloud, this project is extracting the security detection/hunting queries, workbooks and notebooks from Azure Sentinel project which can be used in Azure China Cloud environment (mooncake with Url https://portal.azure.cn):
https://github.com/Azure/Azure-Sentinel

# Before you Start
To start use the security sentinel like query and workbooks, you may need to configure the required data collection to consolidate all required data in a Log Analytics workspace. 
Below is the detailed form for your reference: 

**Connector** | **DataType** | **How to Enable**
----------- | ----------- | --------------
AzureActiveDirectory | AuditLogs | https://docs.azure.cn/zh-cn/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics
AzureActiveDirectory | SigninLogs | https://docs.azure.cn/zh-cn/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics
AzureActivity | AzureActivity | https://docs.azure.cn/zh-cn/azure-monitor/platform/diagnostic-settings
AzureMonitor(Keyvault) | AzureDiagnostics |	https://docs.azure.cn/zh-cn/azure-monitor/insights/azure-key-vault
SecurityEvents | SecurityEvents | https://docs.azure.cn/zh-cn/security-center/security-center-enable-data-collection#data-collection-tier
Syslog | Syslog | https://docs.microsoft.com/en-us/azure/sentinel/connect-syslog
AzureMonitor(IIS) | W3CIISLog |	https://docs.azure.cn/zh-cn/azure-monitor/platform/data-sources-iis-logs
AzureMonitor(Azure Firewall) | AzureDiagnostics| https://docs.microsoft.com/en-us/azure/firewall/firewall-diagnostics
AzureMonitor(Application Gateways/WAF) | AzureDiagnostics | https://docs.azure.cn/zh-cn/application-gateway/application-gateway-diagnostics#enable-logging-through-the-azure-portal
MicrosoftDefenderAdvancedThreatProtection | SecurityAlert | VM side: https://docs.azure.cn/zh-cn/security/fundamentals/antimalware Azure Security Center side: https://docs.azure.cn/zh-cn/security-center/security-center-enable-data-collection
AzureSecurityCenter | SecurityAlert | https://docs.azure.cn/zh-cn/security-center/security-center-enable-data-collection
CEF | CommonSecurityLog | https://docs.microsoft.com/en-us/azure/sentinel/connect-common-event-format
CiscoASA | CommonSecurityLog | https://docs.microsoft.com/en-us/azure/sentinel/connect-common-event-format
ProcessAuditing	| AuditLog_CL | https://msticpy.readthedocs.io/en/latest/data_acquisition/CollectingLinuxAuditLogs.html
TrafficAnalytics | AzureNetworkAnalytics_CL	| https://docs.azure.cn/zh-cn/network-watcher/traffic-analytics
UpdateManagement | Update | https://docs.azure.cn/zh-cn/automation/update-management/update-mgmt-overview or https://docs.azure.cn/zh-cn/security-center/security-center-enable-data-collection
Compliance | SecurityBaseline | https://docs.azure.cn/zh-cn/security-center/security-center-enable-data-collection


# Deploy the Sentinel like Queries and workbooks to your Azure subscription in Mooncake:

## You can choice the template based on your requirement of analytics. 

**category** | **discription** | **required data source** | **optional data source** | **deployment**
----------- | ----------- | -------------- | --------------- | --------
Azure Identity and Activity | Provide security analysis for unabnormal AAD signgs and Azure Actiities such as:   <Br/>brute attacks and password spray attacks on AAD account    <Br/>Suspicioous permission granting      <Br/>anomalous change in signing location      <Br/>unexpected resource deployments | AuditLogs    <Br/>SigninLogsAzure    <Br/>Activity | | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsimonxin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Ftemplate%2FIdentity_Activity.json" target="_blank"><img src="http://azuredeploy.net/deploybutton.png" width="326" height="36"></a>
Network Flows | Provide security analysis on network flows such as:    <Br/>Malicious traffic over IPs and Protocols     <Br/>Allowed and Denied flows trends over NSG     <Br/>Most Attacked resources | AzureNetworkAnalytics_CL | AzureActivity  | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsimonxin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Ftemplate%2Fnetworkwatcher.json" target="_blank"><img src="http://azuredeploy.net/deploybutton.png" width="326" height="36"></a>
Virtual Machine | Provide security analysis on VMs such as:     <Br/>Linux VM SSH logon analytics      <Br/>Linux/Windows VM complainces and update analytics       <Br/>Windows VM Security Event Aanlytics     <Br/>Windows VM uncommon process execution | SecurityEvent   <Br/>Syslog   <Br/>Update | SecurityBaseline   <Br/>SecurityBaselineSummary   <Br/>SecurityAlert   <Br/>ProtectionStatus | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsimonxin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Ftemplate%2Fazurevm.json" target="_blank"><img src="http://azuredeploy.net/deploybutton.png" width="326" height="36"></a>

``` notes
Above templates require two parameters:
For location, please use chinaeast2 only.
Forworkspace, please input your target workspace which you have to import the sentinel like queries. 
```



# Notification
If you want to get notification for one target detection query, you can follow the below steps to create schedule query based alert.
https://docs.azure.cn/zh-cn/azure-monitor/platform/alerts-unified-log

Alert notification will be triggered when detection query has data returned.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/alert.PNG)

# How to use the Sentinel like searches:

There are two options to use the imported Sentinel like queries:

* Option 1: from Azure Portal 
To manage  imported queries, browse to Logs from your Azure Monitor Log Analytics workspace, and choose Query explorer from the top actions menu:

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/savedsearches.png)

* option 2: from Powershell
To loading the queries from command, we can use the powershell cmdlet. Sample code as below: 

```PowerShell
    $resourcegroupname = "<resource_group_of_target_workspace>"
    $workspacename = "<workspace_name>"
    $subid = "<your_subscription_id>"
    $queryname = "Consent to Application Discovery"

    $savedsearches = $(get-AzOperationalInsightsSavedSearch -resourcegroupname $resourcegroupname -workspacename $workspacename).value | where {$_.properties.displayName -eq $queryname}
    if ($savedsearches -ne $NULL) {
		$queryResults = Invoke-LogAnalyticsQuery -Environment "mooncake" -querytype "query" -WorkspaceName $workspacename -SubscriptionId $subid -ResourceGroup $resourcegroupname -Query $savedsearches.properties.query -IncludeRender -IncludeStatistics
	    $queryResults.Results
        $queryResults.Render
		$queryResults.Statistics	
    }
```

note: Invoke-LogAnalyticsQuery is defined in module: \src\LogAnalyticsQuery.psm1

* option 2: Use rest API
To loading the queries in programing, you can refer to the below API document: 
https://docs.microsoft.com/en-us/rest/api/loganalytics/savedsearches/listbyworkspace

Use the REST API, we can use Azure automation account to go through all imported detection and hunting queries. 
The general steps are as below:
1. Prepare the service principal in Azure Automation Account. You can use default principal in AzureRunAsConnection. Or add new service principal. If you use new service principal, you need to modify the demo script to use your new service principal.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aoconnect.png)
2. Grant the below API permissions to the target service principal
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/apipermission.png)
3. Add the Log Analytics Contributor role to the target service principal
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/larole.png)
4. you can then create runbook. Sample source code is in:
 ## [runbook code](src/runbook_runsentinelqueries.ps1)
5. You can also create workbook to show the dection/hunting query result.
Sample code of workbook is in:
 ## [workbook code](workbook/sentinalqueryscanreport.json)

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/sentinelqueryreport.png)



# How to use the Sentinel like workbooks:
To use the workbooks, you can open it from Azure Portal. Browse to workbooks from your Azure Monitor Log Analytics workspace, and choose Open from the top actions menu. Choice the workbooks from Shared Reports list:

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/workbooks.png)

You can follow the workbook page to do analysis. For example, look for unexpected AAD sign-in or activities.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aadsigns.png)
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aaduseractivity.png)

# Detailes of the Sentinel like saved searches and workboos:
You may use the below forms to get the details of the sentinel like searches:
## [Detection Queries](query/detectionquery.csv)
## [Hunting Queries](query/huntingquery.csv)
## [Workbooks](workbook/workbookmetadata.csv)

# Notebook
To use notebooks for theat hunting using Azure Machine Learning in Mooncake, you can go to the below page for more details: 
## [notebooks](https://github.com/simonxin/sentinel-like-notebooks-for-mooncake)


# steps to clean up the sentinel searches
You may use the below sample scripts to cleanup the imported Log Analytics searches: 

```PowerShell
    $resourcegroupname = "<resource_group_of_target_workspace>"
    $workspacename = "<workspace_name>"
    $savedsearches = $(get-AzOperationalInsightsSavedSearch -resourcegroupname $resourcegroupname -workspacename $workspacename).value
    foreach ($search in $savedsearches ) {
        if($search.properties.Category.contains("Sentinel")) {
            $targetid = $search.id.split("/")[-1] 
            Remove-AzOperationalInsightsSavedSearch -ResourceGroupName $resourcegroupname -WorkspaceName $workspacename -SavedSearchId $targetid
        }
    }
```


# steps to clean up the sentinel workbooks
To clean the imported workbooks, you can go to the Azure Portal. Go to the target resource group and filter with Azure Workboos resource type. Select the workbooks you want to delete (Sentinel like workbooks will be started with security - in name), and choose Delete from the top actions menu:

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/workbookresource.png)


# steps to clean up the sentinel dashboards
To clean the imported dashboard, you can go to the Azure Portal. Go to the target resource group and filter with shared dashboard resource type. Select the dashboard you want to delete, and choose Delete from the top actions menu:

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/dashboardresource.png)


