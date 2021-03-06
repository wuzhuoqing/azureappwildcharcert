# Introduction 
Docker image to be run in Azure container instance service and obtain/update let's encrypt wild char cert for azure web site.

# Getting Started

1.	Installation process

  Create azure container instance with docker hub image `wuzhuoqing/azurecert:azurewildcharcert`. (`az container create --resource-group myResourceGroup --file az_container.yaml` check [az_container.yaml](https://github.com/wuzhuoqing/azureappwildcharcert/blob/master/az_container.yaml) for details)
  
  Grant azure container instance managed identify access to keyvault to get secret and import cert.
  
  Grant azure container instance managed identify access to add cert and bind ssl to app service (May need ResourceGroup contributor role to add cert)
  
  Assign azure container instance below Environment variables and (maybe optionally) create an azure fileshare and attach to /usr/src/app/.lego/accounts/ (ref to [az_container.yaml](https://github.com/wuzhuoqing/azureappwildcharcert/blob/master/az_container.yaml) for details)

* `KEY_VAULT_URL=https://yourvault.vault.azure.net/` Keyvault used to save secret and cert

* `CONFIG_INDEX=EntryToGet` The secret entry in keyvault to get other configs. comma separated. For now 3 entries are needed. For example, the value can be `CF-ZONE-API-TOKEN,CF-DNS-API-TOKEN,WEB-CERT` which means 
  * `CF-ZONE-API-TOKEN` secret entry store cloudflare dns zone api token .
  * `CF-DNS-API-TOKEN` for dns api token.
  * `WEB-CERT` is the cert entry to update in keyvault.

* `DOMAIN_NAME=domain name to get wild char` lower case like `example.com`

* `EMAIL_NAME=email` used for let's entrypt cert account and possible also the cloudflare account email.

* `DNS_PROVIDER=Godaddy` use Godaddy as DNS_PROVIDER. Else will use CloudFlare.

* `AZURE_SUBSCRIPTION_ID=GUID_OF_SUBSCRIPTION`

* `SITE_RESOURCE_GROUP=WebSiteResourceGroup`

After the container instance is created. Create an azure function to start it say every 3 days. Can use [AzureContainerTimerTrigger](https://github.com/wuzhuoqing/AzureContainerTimerTrigger). Azure function managed identify need to have permission to the container instance. Due to an [issue](https://github.com/Azure/ms-rest-nodeauth/issues/86) only system assigned identify is supported for now. Azure function [timer trigger may not be reliable](https://github.com/Azure/azure-functions-host/issues/5836) so we may create another azure function with http trigger and use some 3rd party scheduler to trigger it.

For local debugging or to use azure app service-principal instead of managed identity those extra secure env value can be added. The azure app need to have permission to read secret and import/update cert in keyvault.

* `AZURE_CLIENT_ID=`

* `AZURE_TENANT_ID=`

* `AZURE_CLIENT_SECRET=`

2.	Software dependencies

The default implementation use CloudFlare as DNS provider. see [lego doc](https://go-acme.github.io/lego/dns/cloudflare/) for more details. It can be easily changed to any other DNS provider lego supports though.

3.	Latest releases
4.	API references

# Build and Test
TODO: Describe and show how to build your code and run the tests. 

# Contribute
TODO: Explain how other users and developers can contribute to make your code better. 

If you want to learn more about creating good readme files then refer the following [guidelines](https://docs.microsoft.com/en-us/azure/devops/repos/git/create-a-readme?view=azure-devops). You can also seek inspiration from the below readme files:
- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)
