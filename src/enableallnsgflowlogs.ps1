
# Please replace the below parameters:
# location = actual locations for Network Security Groups
# storageAccountName = storage account which will store NSG flow logs. This storage account should be in the same location as network security group
# workspcename = your actual log analytics workspace name
# TrafficAnalyticsInterval = NSG flow log analytics interval. Value can be 10 or 60 minutes
# nsglogFormatVersion = NSG flow logs format version. Value can be 1 or 2. when set the format version to 2, packet size will be stored in Log A workspace 


$location = "<your_NSG_location>"
$storageAccountName = "<storage_account_name>"
$workspacename = "<log_analytics_workspace_name>"
$TrafficAnalyticsInterval = 10
$nsglogFormatVersion = 2

$NetworkWatcherResourceGroup = "NetworkWatcherRG"
$storageAccount = Get-AzStorageAccount | where {($_.storageaccountname -eq $storageAccountName) -and ($_.PrimaryLocation -eq $location)}
$workspace = Get-AzOperationalInsightsWorkspace | where {$_.name -eq $workspacename}


 if ( (($storageAccount | measure-object).count -eq 0) -or (($workspace | measure-object).count -eq 0)  ){
    write-host "there is no storage accout existing in the target location or Log Analytics workspace does not exist"
 } else {

    $NW = Get-AzNetworkWatcher -location $location -erroraction ignore 
    if (($NW| measure-object).count -eq 0) {
        $NWRG = get-azresourcegroup -name $NetworkWatcherResourceGroup -erroraction ignore
        if (($NWRG | measure-object).count -eq 0) {
            New-AzResourceGroup -Name $NetworkWatcherResourceGroup  -Location $location
        }
        
        Register-AzResourceProvider -ProviderNamespace Microsoft.Insights
        $NWName = "NetworkWatcher_"+$location
        $NW =  New-AzNetworkWatcher -location $location -ResourceGroupName $NetworkWatcherResourceGroup -Name $NWName 
    }

    $nsgs = Get-AzNetworkSecurityGroup | where {$_.Location -eq $location}

    foreach ($nsg in $nsgs) {
        Set-AzNetworkWatcherConfigFlowLog -NetworkWatcher $NW -TargetResourceId $nsg.Id -StorageAccountId $storageAccount.Id -EnableFlowLog $true -FormatType Json -FormatVersion $nsglogFormatVersion -EnableTrafficAnalytics -TrafficAnalyticsInterval $TrafficAnalyticsInterval -WorkspaceResourceId $workspace.ResourceId -WorkspaceGUID $workspace.CustomerId -WorkspaceLocation $workspace.Location
    }

}
