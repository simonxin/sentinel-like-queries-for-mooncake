# Introduction
Microsoft Azure Sentinel is a scalable, cloud-native, security information event management (SIEM) and security orchestration automated response (SOAR) solution. 
For more information about Azure Sentinel, you can go to the below link: 
https://azure.microsoft.com/en-us/resources/videos/introducing-microsoft-azure-sentinel/

 To allow customers to leverage the security experience in Azure China Cloud, this project is extracting the security detection/hunting queries, workbooks and notebooks from Azure Sentinel project which can be used in Azure China Cloud environment (mooncake with Url https://portal.azure.cn):
https://github.com/Azure/Azure-Sentinel

You may follow the introduction in the below section to use the queries. 

# Enable the required data collections. 
To start use the security sentinel like query and workbooks, you may need to configure the required data collection to consolidate all required data in a Log Analytics workspace. If there is no existing Log Analytics workspace, you can follow the below article to create a new one.
https://docs.azure.cn/zh-cn/azure-monitor/learn/quick-create-workspace
Below is the detailed list for all data collection we can used for your reference: 

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


# Deploy the Overall Dashboard to your Azure subscription in Mooncake:

As an overview, we can use predefined dashboard to show overall status for both VM Perf and Security. 
To deploy the dashboard, you can use the below powershell commands:
```
# Please replace the below paremeters:
# workspce = your actual log analytics workspace name
# resouworkspaceresourcegroup = your actual log analytics workspace resource group
# targetresourcegroup = resource group you want to deploy the dashboard
# templatefile = 
# Use chinaeast2 as the location as log analytics service only available in this region
$workspace = "<your_LogA_workspace_name>"
$workspaceresourcegroup = "<your_LogA_workspace_resource_group>"
$targetresourcegroup = "<resource_group_for_dashboard>"
$templatefile = "<downloaded_json_file_full_path>"
$location = "chinaeast2"

# Define parameters
$params = @{
    workspace = $workspace
    resourcegroup = $workspaceresourcegroup
    location = $location
}

$rg = Get-AzResourceGroup -Name $targetresourcegroup -ErrorAction SilentlyContinue

if ($rg -eq $null) {
    $rg =New-AzResourceGroup $targetresourcegroup -Location $location
}

# do group deployment
New-AzResourceGroupDeployment -ResourceGroupName $targetresourcegroup -Name $targetresourcegroup `
 -TemplateFile $templatefile `
 -TemplateParameterObject $params `
 -Verbose

```

## Template by category 
**category** | **discription** | **required data source** | **template**
----------- | ----------- | -------------- | --------
Azure AD Signing | Azure dashboard which will show overview of Azure AD signin operations | SigninLogs | [azureadsignins.json](dashboard/azureadsignins.json)
Azure AD Operations | Azure dashboard which will provide overview of sensitive Azure AD operations like grant permissions or add new users etc | AuditLog | [Azure_AD_Audit_logs.json](dashboard/Azure_AD_Audit_logs.json)
Azure Activity | Azure dashboard which will show overview of Azure activities like resource creation, updating and deletion | AzureActivity | [Azure_Activity.json](dashboard/Azure_Activity.json)
Network Flows | Azure Dashboard which will show overview analysis on network flows such as:    <Br/>1) Malicious traffic over IPs and Protocols,    <Br/>2) Allowed and Denied flows trends over NSG,    <Br/>3) Most Attacked resources | AzureNetworkAnalytics_CL | [azurenetworkwatcher.json](dashboad/azurenetworkwatcher.json)
Virtual Machine Performance | Azure Dashboard which will show performance overview on monitored Azure VMs | Perf | [PerformLATemplate.json](dashboard/PerformLATemplate.json)
Windows Security Events | Azure Dashboard which will show overview analytics on collected Windows Security Events from Windows VM with Azure Security Center license | SecurityEvent | [identity_and_access.json](dashboard/identity_and_access.json)
Application Gateway - WAF | Azure Dashboard which will show overview analytics on collected WAF access logs |AzureDiagnostics | [Microsoft_WAF.json](dashboard/Microsoft_WAF.json)


# Deploy the Sentinel like Queries and workbooks to your Azure subscription in Mooncake:

To simplify the usage of threat check based on Sentinel security experiences, we used ARM template to package the query and workbooks based on monitoring scenarios. 
To deploy the workboos and queries, you can use the below powershell commands:
```
# Please replace the below paremeters:
# workspce = your actual log analytics workspace name
# resouworkspaceresourcegroup = your actual log analytics workspace resource group
# targetresourcegroup = resource group you want to deploy the dashboard
# templatefile = 
# Use chinaeast2 as the location as log analytics service only available in this region
$workspace = "<your_LogA_workspace_name>"
$targetresourcegroup = "<resource_group_for_workbooks_and_queries>"
$templatefile = "<downloaded_json_file_full_path>"
$location = "chinaeast2"

# Define parameters
$params = @{
    workspace = $workspace
    location = $location
}

$rg = Get-AzResourceGroup -Name $targetresourcegroup -ErrorAction SilentlyContinue

if ($rg -eq $null) {
    $rg =New-AzResourceGroup $targetresourcegroup -Location $location
}

# do group deployment
New-AzResourceGroupDeployment -ResourceGroupName $targetresourcegroup -Name $targetresourcegroup `
 -TemplateFile $templatefile `
 -TemplateParameterObject $params `
 -Verbose

```


## Template by category 
**category** | **discription** | **required data source** | **optional data source** | **ARM template Conent**
----------- | ----------- | -------------- | --------------- | --------
Azure Identity and Activity | Provide security analysis for unabnormal AAD signgs and Azure Actiities such as:     <Br/>1) brute attacks and password spray attacks on AAD account,    <Br/>2) Suspicioous permission granting,    <Br/>3) anomalous change in signing location,    <Br/>4) unexpected resource deployments | AuditLogs    <Br/>SigninLogsAzure    <Br/>Activity | | [Identity_Activity.json](template/Identity_Activity.json)
Network Flows | Provide security analysis on network flows such as:    <Br/>1) Malicious traffic over IPs and Protocols,    <Br/>2) Allowed and Denied flows trends over NSG,    <Br/>3) Most Attacked resources | AzureNetworkAnalytics_CL | AzureActivity  | [networkwatcher.json](template/networkwatcher.json)
Virtual Machine | Provide security analysis on VMs such as:    <Br/>1) Linux/Windows logon analytics,    <Br/>2) Linux/Windows VM complainces and update analytics,    <Br/>3) Windows VM Security Event Aanlytics,    <Br/>4) Windows VM process execution analytics    <Br/>5)Access on Windows VM by protocol like SMB/Kerberos/NTLM| SecurityEvent   <Br/>Syslog   <Br/>Update | Event    <Br/>SecurityBaseline   <Br/>SecurityBaselineSummary   <Br/>SecurityAlert   <Br/>ProtectionStatus | [azurevm.json](template/azurevm.json)
Azure Diagnostic | Provide security analysis on Azure Resource Diagnostic log such as:    <Br/>1) Azure KeyVault sentive operatins analytics,    <Br/>2) WAF (Web Application Firewall) access log analytics,    <Br/>3) Azure Firewall trace anlytics | AzureDiagnostics | | [azurediagnostics.json](template/azurediagnostics.json)
IIS Log | Provide security analysis on IIS logs (limited to Windows VM only) to provide insights theat checks | W3CIISLog | | [IIS.json](template/IIS.json)
Common Event Format | Provide security analysis on CEF log such as:    <Br/>1) Cisco CEF logs,    <Br/>2) Hardware WAF CEF logs | CommonSecurityLog | SecurityAlerts | [CEF.json](template/CEF.json)

``` notes
    1) Above templates require two parameters:
    For location, please use chinaeast2 only.
    For workspace, please input your target workspace which you have to import the sentinel like queries. 
    2) Once the data collection is enabled and the related template is imported, you may need to wait for at least one day to allow the query and workbook have data required for presentation
```

# How to use the Sentinel like workbooks:
To use the workbooks, you can open it from Azure Portal. Browse to workbooks from your Azure Monitor Log Analytics workspace, and choose Open from the top actions menu. Choice the workbooks from Shared Reports list:

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/workbooks.png)

You can follow the workbook page to do analysis. For example, look for unexpected AAD sign-in or activities.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aadsigns.png)
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aaduseractivity.png)



# Execute the imported Queries and do investigating based on the query results
The imported queries are under the folders which are named as Sentinel-<Scenario_name>-[Detection|Hunting]-<Priority>
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/savedsearches.png)

You can run the queries manually. Or you can use Azure Automation to run the imported Sentinel like queries with a defined schedule in Azure Automation Account. Below is the ARM template to import the related runbook and workbook to run the queries and do invetigating: 

[sentinelreport.json](template/sentinelreport.json)

* To use the runbook, you need to complete the below steps:

1) Get the service principal of automation connector named as AzureRunAsConnection. 
You can get the application ID from Azure Automation Account connections page:
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/automationconnection.png)
note: If there is no such connection, you may follow the steps in the below article to create one: 
https://docs.azure.cn/zh-cn/automation/automation-connections

Then in the Azure Active Directory and All Applications page, you can get the service principal name of the selected aplication ID: 
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/automationconnection2.png)

2) Grant the Log Analytics Contributor role for the service principal in step 1) on the targeted log analytics workspace:
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/automationconnection3.png)

3) From automation account, locate the runbook named as "PollingSentinelQueries". In Schedule page, click on "Add a schedule" and follow the wizard to create a new schedule to execute the runbook.
As a sample, you can create a runbook schedule to polling detection query once per hour (Set QUERYTYPE = Detection). 
Then create a runbook schedule to polling hunting query once per day (Set QUERYTYPE = Hunting). 

* Once the automation is triggered, we will check the report in workbook named as "security - Sentinel query report" and do invetigating. 
For example, you will see the related detection rule which has data returned in the Detection Rule triggered form.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample1.png)
Click on the select rule, you will see the details in the "Selected rule query details" form:
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample2.png)
If network watcher NSG flow logs are enabled, we can input the IP address and select network flow types to get all related network flows based on input IP for further investigating.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample3.png)


# Notification
If you want to get notification for one target detection query, you can follow the below steps to create schedule query based alert.
https://docs.azure.cn/zh-cn/azure-monitor/platform/alerts-unified-log

Alert notification will be triggered when detection query has data returned.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/alert.PNG)

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


