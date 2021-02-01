# Introduction
Microsoft Azure Sentinel is a scalable, cloud-native, security information event management (SIEM) and security orchestration automated response (SOAR) solution. 
For more information about Azure Sentinel, you can go to the below link: 
https://azure.microsoft.com/en-us/resources/videos/introducing-microsoft-azure-sentinel/

 To allow customers to leverage the security experience in Azure China Cloud, this project is extracting the security detection/hunting queries, workbooks and notebooks from Azure Sentinel project which can be used in Azure China Cloud environment (mooncake with Url https://portal.azure.cn):
https://github.com/Azure/Azure-Sentinel

You may follow the introduction in the below section to use the queries. 

# Idea

The idea for this solution is to extract detection and hunting queries from Sentinel project. Then build workbook and dashboard based on such queries to help customer do threat detection and analytics based on those detection and hunting queries. 

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/ideas.png)

Dashboard, workbooks and queries are packing in ARM template which is categorized by common monitoring scenarios like AAD authentication, Azure Activities, Network Flows, Virtual Machine identity and Access. 
Azure automation is used to run extracted detection and hunting queries in a defined schedule and show results in workbook for further threat detection and analytics. 

# Template Content

Below is the detailed forms for categorized ARM template

## Dashboard Template by category 
**category** | **description** | **required data source** | **template**
----------- | ----------- | -------------- | --------
Azure AD Signing | Azure dashboard which will show overview of Azure AD signin operations | SigninLogs | [azureadsignins.json](dashboard/azureadsignins.json)
Azure AD Operations | Azure dashboard which will provide overview of sensitive Azure AD operations like grant permissions or add new users etc | AuditLog | [Azure_AD_Audit_logs.json](dashboard/Azure_AD_Audit_logs.json)
Azure Activity | Azure dashboard which will show overview of Azure activities like resource creation, updating and deletion | AzureActivity | [Azure_Activity.json](dashboard/Azure_Activity.json)
Network Flows | Azure Dashboard which will show overview analysis on network flows such as:    <Br/>1) Malicious traffic over IPs and Protocols,    <Br/>2) Allowed and Denied flows trends over NSG,    <Br/>3) Most Attacked resources | AzureNetworkAnalytics_CL | [azurenetworkwatcher.json](dashboad/azurenetworkwatcher.json)
Virtual Machine Performance | Azure Dashboard which will show performance overview on monitored Azure VMs | Perf | [PerformLATemplate.json](dashboard/PerformLATemplate.json)
Windows Security Events | Azure Dashboard which will show overview analytics on collected Windows Security Events from Windows VM with Azure Security Center license | SecurityEvent | [identity_and_access.json](dashboard/identity_and_access.json)
Application Gateway - WAF | Azure Dashboard which will show overview analytics on collected WAF access logs |AzureDiagnostics | [Microsoft_WAF.json](dashboard/Microsoft_WAF.json)


## Workbook and Queries Template by category 
**category** | **description** | **required data source** | **optional data source** | **ARM template Conent**
----------- | ----------- | -------------- | --------------- | --------
Azure Identity and Activity | Provide security analysis for unabnormal AAD signgs and Azure Actiities such as:     <Br/>1) brute attacks and password spray attacks on AAD account,    <Br/>2) Suspicioous permission granting,    <Br/>3) anomalous change in signing location,    <Br/>4) unexpected resource deployments | AuditLogs    <Br/>SigninLogsAzure    <Br/>Activity | | [Identity_Activity.json](template/Identity_Activity.json)
Network Flows | Provide security analysis on network flows such as:    <Br/>1) Malicious traffic over IPs and Protocols,    <Br/>2) Allowed and Denied flows trends over NSG,    <Br/>3) Most Attacked resources | AzureNetworkAnalytics_CL | AzureActivity  | [networkwatcher.json](template/networkwatcher.json)
Virtual Machine | Provide security analysis on VMs such as:    <Br/>1) Linux/Windows logon analytics,    <Br/>2) Linux/Windows VM complainces and update analytics,    <Br/>3) Windows VM Security Event Aanlytics,    <Br/>4) Windows VM process execution analytics    <Br/>5)Access on Windows VM by protocol like SMB/Kerberos/NTLM| SecurityEvent   <Br/>Syslog   <Br/>Update | Event    <Br/>SecurityBaseline   <Br/>SecurityBaselineSummary   <Br/>SecurityAlert   <Br/>ProtectionStatus | [azurevm.json](template/azurevm.json)
Azure Diagnostic | Provide security analysis on Azure Resource Diagnostic log such as:    <Br/>1) Azure KeyVault sentive operatins analytics,    <Br/>2) WAF (Web Application Firewall) access log analytics,    <Br/>3) Azure Firewall trace anlytics | AzureDiagnostics | | [azurediagnostics.json](template/azurediagnostics.json)
IIS Log | Provide security analysis on IIS logs (limited to Windows VM only) to provide insights theat checks | W3CIISLog | | [IIS.json](template/IIS.json)
Common Event Format | Provide security analysis on CEF log such as:    <Br/>1) Cisco CEF logs,    <Br/>2) Hardware WAF CEF logs | CommonSecurityLog | SecurityAlerts | [CEF.json](template/CEF.json)


## Detailes of the Sentinel like saved searches and workboos:
You may use the below forms to get the details of the sentinel like searches:
## [Detection Queries](query/detectionquery.csv)
## [Hunting Queries](query/huntingquery.csv)
## [Workbooks](workbook/workbookmetadata.csv)

# Automation runbooks and analytics workbook:

You can run the queries manually. Or you can use Azure Automation to run the imported Sentinel like queries with a defined schedule in Azure Automation Account. Below is the ARM template to import the related runbook and workbook to run the queries and do invetigating: 

[sentinelreport.json](template/sentinelreport.json)


# How to deploy

The whole process to deploy the solution whill include the below steps:
* Determine the monitoring scenario and download required ARM template
* Enable data collection for required monitoring scenario
* Deploy template
* Do log analytics in dashboard and workbooks
* Deploy automation runbooks and analytics workbook
* Enable Azure Monitor Rule Alert

You may follow the steps in the below deployment guide:

[Deployment Guide](doc/deploymentguide.pdf)

# How to use:

* Workbooks
To use the workbooks, you can open it from Azure Portal. Browse to workbooks from your Azure Monitor Log Analytics workspace, and choose Open from the top actions menu. Choice the workbooks from Shared Reports list:

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/workbooks.png)

You can follow the workbook page to do analysis. For example, look for unexpected AAD sign-in or activities.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aadsigns.png)
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aaduseractivity.png)

* Runbooks
To use the runbook, you need to complete the below steps:

1) Get the service principal of automation connector named as AzureRunAsConnection. 
You can get the application ID from Azure Automation Account connections page:
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/automationconnection.png)
note: If there is no such connection, you may follow the steps in the below article to create one: 
https://docs.azure.cn/zh-cn/automation/automation-connections

Then in the Azure Active Directory and All Applications page, you can get the service principal name of the selected aplication ID: 
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/automationconnection2.png)

2) Grant the Log Analytics Contributor role for the service principal in step 1) on the targeted log analytics workspace:
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/automationconnection3.png)

3) Once the automation is triggered, we will check the report in workbook named as "security - Sentinel query report" and do invetigating. 
For example, you will see the related detection rule which has data returned in the Detection Rule triggered form.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample1.png)
Click on the select rule, you will see the details in the "Selected rule query details" form:
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample2.png)
If network watcher NSG flow logs are enabled, we can input the IP address and select network flow types to get all related network flows based on input IP for further investigating.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample3.png)

* Notification
If you want to get notification for one target detection query, you can follow the below steps to create schedule query based alert.
https://docs.azure.cn/zh-cn/azure-monitor/platform/alerts-unified-log

Alert notification will be triggered when detection query has data returned.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/alert.PNG)

# Notebook
As an advanced usage, we can also use azure notebooks for theat hunting. You can go to the below page for more details: 
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


