# Usage
This project is extracting the security detection/hunting queries and workbooks from Azure Sentinel project which can be used in Mooncake environment:
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


# Deploy the Sentinel like Detection Queries to your Azure subscription in Mooncake:
Use below template to deploy the Azure Sentinel Like Detection Queries to your Azure subscription:
<a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fquery%2FSentinel-Insight-Detection.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

This template requires two parameters:
For location, please use chinaeast2 only.
Forworkspace, please input your target workspace which you have to import the sentinel like queries. 

# Notification
If you want to get notification for one target detection query, you can follow the below steps to create schedule query based alert.
https://docs.azure.cn/zh-cn/azure-monitor/platform/alerts-unified-log


# Deploy the Sentinel like Hunting Queries to your Azure subscription in Mooncake:
Use below template to deploy the Azure Sentinel Like Hunting Queries to your Azure subscription:
<a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fquery%2FSentinel-Insight-Hunting.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>


This template requires two parameters:
For location, please use chinaeast2 only.
Forworkspace, please input your target workspace which you have to import the sentinel like queries. 


# Deploy the Sentinel like workbooks to your Azure subscription in Mooncake:

Use below template to deploy the Azure Sentinel Like workbooks to your Azure subscription:

<a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fworkbook%2Fworkbook_template.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>


This template requires two parameters:
For location, please use chinaeast2 only.
Forworkspace, please input your target workspace which you have to import the workbooks. 

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

* option 3: Use rest API
To loading the queries in programing, you can refer to the below API document: 
https://docs.microsoft.com/en-us/rest/api/loganalytics/savedsearches/listbyworkspace


# How to use the Sentinel like workbooks:
To use the workbooks, you can open it from Azure Portal. Browse to workbooks from your Azure Monitor Log Analytics workspace, and choose Open from the top actions menu. Choice the workbooks from Shared Reports list:

![](https://github.com/simonxin/sentinel-like-queries-for-mooncake/blob/master/image/workbooks.png)


# Detailes of the Sentinel like saved searches and workboos:
You may use the below forms to get the details of the sentinel like searches:
## [Detection Queries](query/detectionquery.csv)
## [Hunting Queries](query/huntingquery.csv)
## [Workbooks](workbook/workbookmetadata.csv)

# Dashboard

You can use sample dashboard to view security related event/logs which are stored in the targeted Log Anaytics Workspace.
Below are the sample dashboards: 
**name** | **disscription** | **deploy to Azure**
----------- | ----------- | --------------
Azure Activity | Gain extensive insight into your organization's Azure Activity by analyzing, and correlating all user operations and events.\nYou can learn about all user operations, trends, and anomalous changes over time.nThis dashboard gives you the ability to drill down into caller activities and summarize detected failure and warning events. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2FAzure_Activity.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
Identity & Access | Gain insights into Identity and access operations by collecting and analyzing security logs, using the audit and sign-in logs to gather insights into use of Microsoft products.\nYou can view anomalies and trends across login events from all users and machines. This dashboard also identifies suspicious entities from login and access events. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2Fidentity_and_access.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
Insecure Protocols | Gain insights into Insecure protocol traffic by collecting and analyzing security events from Microsoft products.\nYou can view analytics and quickly identify use of weak authentication as well as sources of legacy protocol traffic, like NTLM and SMBv1.\nYou will also have the ability to monitor use of weak ciphers, allowing you to find weak spots in your organization's security. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2FInsecure_Protocols.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
Azure Network Watcher | Gain deeper understanding of your organization's Azure network traffic by analyzing, and correlating Network Security Group flow logs. \nYou can trace malicious traffic flows, and drill down into their protocols, source and destination IP addresses, machines, countries, and subnets. \nThis dashboard also helps you protect your network by identifying weak NSG rules. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2FAzureNetworkWatcher.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
Azure AD Sign-in logs | Gain insights into Azure Active Directory by connecting Azure Sentinel and using the sign-in logs to gather insights around Azure AD scenarios. \nYou can learn about sign-in operations, such as user sign-ins and locations, email addresses, and  IP addresses of your users, as well as failed activities and the errors that triggered the failures. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2FAzure_AD_Signins.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
Linux machines | Gain insights into your workspaces' Linux machines by connecting Azure Sentinel and using the logs to gather insights around Linux events and errors. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2FLinux_machines.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
Microsoft Web Application Firewall (WAF) | Gain insight into your organization's Azure web application firewall (WAF). You will get visibility in to your application gateway firewall and application gateway access events. You can view anomalies and trends across ports, URL addresses, IP addresses, protocols ,and more. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2FMicrosoft_WAF.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
Azure AD Audit logs | Gain insights into Azure Active Directory by connecting Azure Sentinel and using the audit logs to gather insights around Azure AD scenarios. \nYou can learn about user operations, including password and group management, device activities, and top active users and apps. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2FAzure_AD_Audit_Logs.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
Azure Firewall | Gain insights into Azure Firewall events. You can get learn about your application and network rules, see statistics for firewall activities across URLs, ports, and addresses. | <a href="https://portal.azure.cn/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FSimonXin%2Fsentinel-like-queries-for-mooncake%2Fmaster%2Fdashboard%2FAzure_Firewall.json" 
target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

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



