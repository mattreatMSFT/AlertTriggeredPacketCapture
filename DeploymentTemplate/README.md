# Deploy an Azure Function using an ARM template

The AlertPacketCapture branch contains a working version of the deployment template, tailored for a real version of a function that processes Azure Monitor Alerts and triggers a subsequent packet capture on the resource that fired the alert.

[![Deploy to Azure](http://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FmattreatMSFT%2FAlertTriggeredPacketCapture%2Fmaster%2FDeploymentTemplate%2FazureDeploy.json
)

## Overview

The steps to fully implement the Azure Network Watcher Alert Packet Capture Connector are:  
* Gather the settings below.
* Click the "Deploy to Azure" button below.
* Authenticate to the Azure Portal (if necessary)
* Fill in the form with the setting values
* Wait a few minutes for the function to be created and deployed
* Configure Alerts on resources and provide the URL of the the function - ~/Function1

## Settings

* AppName                     - this is the name of the function app. In the Azure Portal, this is the name that will appear in the list of resources.  
   Example: ```MyNSGApp```  
* appServicePlanTier          - "Free", "Shared", "Basic", "Standard", "Premium", "PremiumV2"  
   Example: ```Standard```
* appServicePlanName          - depends on tier, for full details see "Choose your pricing tier" in the portal on an App service plan "Scale up" applet.  
   Example: For standard tier, "S1", "S2", "S3" are options for plan name
* appServicePlanCapacity      - how many instances do you want to set for the upper limit?  
   Example: For standard tier, S2, set a value from 1 to 10
* githubRepoURL                     - this is the URL of the repo that contains the function app source. You would put your fork's address here.  
   Example: ```https://github.com/microsoft/AzureNetworkWatcherNSGFlowLogsConnector```
* githubRepoBranch                  - this is the name of the branch containing the code you want to deploy.  
   Example: ```master```
* PacketCaptureStorageAccount    - this is the name of the storage account where packet captures will be saved
   Example: ```/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{storageAccountName}```
* ClientId - this is the clientId of the Service Principle used to authenticate to Azure Resource Manager
   Example: ```00000000-0000-0000-0000-000000000000``` 
* clientKey - this is the client key associated with the service princple
   Example: ```00000000-0000-0000-0000-000000000000``` 
* TenantId - this is the Azure Active Directory TenantId 
   Example: ```00000000-0000-0000-0000-000000000000``` 
