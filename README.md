# Introduction
Microsoft Azure Sentinel is a scalable, cloud-native, security information event management (SIEM) and security orchestration automated response (SOAR) solution. 
For more information about Azure Sentinel, you can go to the below link: 
https://azure.microsoft.com/en-us/resources/videos/introducing-microsoft-azure-sentinel/

 To allow customers to leverage the security experience in Azure China Cloud, this project is extracting the security detection/hunting queries, workbooks and notebooks from Azure Sentinel project which can be used in Azure China Cloud environment (mooncake with Url https://portal.azure.cn):
https://github.com/Azure/Azure-Sentinel

You may follow the introduction in the below section to use the queries. 

# Idea

The idea for this solution is to extract detection and hunting queries from Sentinel project. Then build workbook and dashboard based on such queries to help customer do threat detection and analytics based on those detection and hunting queries. 

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/ideas.PNG)

Those detection and hunting queries, dashboard, workbooks are packed as ARM templates which is categorized by common monitoring scenarios like AAD authentication, Azure Activities, Network Flows, Virtual Machine identity and Access. 
Azure Logic app is defined to run Azure automation runbook which will execute security queries based on enabled monitoring categories. Notification email will be formatted and send out as expected. 

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/strcuture.png)


# How to deploy and use

You may follow the steps in the below deployment guide:

## [Deployment Guide](doc/deploymentguide.pdf)

## Sample usage:

### Security Reports

For example, you will see the related detection rule which has data returned in the Detection Rule triggered form.
* list alerts by category
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample1.png)
* list alerts and show details for selected alerts
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample2.png)
* run hunting queries for selected category to find more potential risky
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/detectionrulesample3.png)
* Network exploration for selected public IP (potential malicious IP)
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/exploration1.png)
* AD operations and AAD signing exploration for selected public IP (potential malicious IP)
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/exploration2.png)
* Network exploration for selected internal IP (potential effected VM IP)
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/exploration3.png)
* Trace details from selected VM and internal IP (potential effected VM)
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/exploration4.png)


### Notification
Notification format is defined in the logic app workflows with CSS format.
You may change the content if required.
Sample notification format as: 
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/notification.png)


### visualization analysis (workbook and Dashbaord)
* Sample data analytics to look for unexpected AAD sign-in or activities.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aadsigns.png)
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/aaduseractivity.png)
* Sample data analytics to look for network watcher logs.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/networkwatcher.png)
* Sample data analytics to look for VM update and CCE report.
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/vm.png)
* Dashboard show which can share with other users
![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/dashboard.png)


# Template Content

Below is the detailed forms for categorized ARM template

## Detailes of the Sentinel like saved security queries and workboos:
You may use the below forms to get the details of the security rules:
## [Security Queries](query/securityrules.csv)
You may use the below forms to get the details of the workbooks:
## [Workbooks](workbook/workbookmetadata.csv)

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


## Workbook Template by category 
**category** | **description** | **required data source** | **optional data source** | **ARM template Conent**
----------- | ----------- | -------------- | --------------- | --------
Azure Identity and Activity | Provide security analysis for unabnormal AAD signgs and Azure Actiities such as:     <Br/>1) brute attacks and password spray attacks on AAD account,    <Br/>2) Suspicioous permission granting,    <Br/>3) anomalous change in signing location,    <Br/>4) unexpected resource deployments | AuditLogs    <Br/>SigninLogsAzure    <Br/>Activity | | [Identity_Activity.json](template/Identity_Activity.json)
Network Flows | Provide security analysis on network flows such as:    <Br/>1) Malicious traffic over IPs and Protocols,    <Br/>2) Allowed and Denied flows trends over NSG,    <Br/>3) Most Attacked resources | AzureNetworkAnalytics_CL | AzureActivity  | [networkwatcher.json](template/networkwatcher.json)
Virtual Machine | Provide security analysis on VMs such as:    <Br/>1) Linux/Windows logon analytics,    <Br/>2) Linux/Windows VM complainces and update analytics,    <Br/>3) Windows VM Security Event Aanlytics,    <Br/>4) Windows VM process execution analytics    <Br/>5)Access on Windows VM by protocol like SMB/Kerberos/NTLM| SecurityEvent   <Br/>Syslog   <Br/>Update | Event    <Br/>SecurityBaseline   <Br/>SecurityBaselineSummary   <Br/>SecurityAlert   <Br/>ProtectionStatus | [azurevm.json](template/azurevm.json)
Azure Diagnostic | Provide security analysis on Azure Resource Diagnostic log such as:    <Br/>1) Azure KeyVault sentive operatins analytics,    <Br/>2) WAF (Web Application Firewall) access log analytics,    <Br/>3) Azure Firewall trace anlytics | AzureDiagnostics | | [azurediagnostics.json](template/azurediagnostics.json)
Common Event Format | Provide security analysis on CEF log such as:    <Br/>1) Cisco CEF logs,    <Br/>2) Hardware WAF CEF logs | CommonSecurityLog | SecurityAlerts | [CEF.json](template/CEF.json)


## Playbook templates
**name** | **description** | **required API connector**  | **template**
----------- | ----------- | -------------- | -------------
block-bruteforceattackip | Logic App used to block malicious IP where has raised brute force attack |  <Br/>1) Azure Security Center   <Br/>2) Office 365 | [logicapp_blockbruteforceattachip.json](template/logicapp_blockbruteforceattachip.json)
isolate-infectedVM | Logic App used to isolate infected VM | <Br/>1) Azure Security Center   <Br/>2) Office 365 | [logicapp_blockbruteforceattachip.json](template/logicapp_blockbruteforceattachip.json)
none | template used to create customized user role for logic app | | [logicapp_approledefinition.json](template/logicapp_approledefinition.json)


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


