import db.database as db
import logging
import collections
import time
from threading import Lock
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.authorization import AuthorizationManagementClient
from msrestazure.azure_exceptions import CloudError
from azure.mgmt.resource import SubscriptionClient
from dateutil.parser import parse
lock = Lock()

logger = logging.getLogger('cloud_monitor.Utils')

def getTenantId(temp=0):
    return 1

class ctlogger(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return '[%s] %s' % (self.extra['custname'],msg), kwargs

class AzureUtils:

    # Constants
    STATUS_LOGIN                = 100
    STATUS_LOGIN_FAILED         = 101
    STATUS_LOGIN_COMPLETED      = 102

    STATUS_DISCOVERY_FAILED     = 200
    STATUS_DISCOVERY_COMPLETED  = 201

    STATUS_MONITOR_FAILED       = 300
    STATUS_MONITOR_STARTED      = 301
    STATUS_FLOW_STARTED         = 302

    STATUS_FLOW_FAILED          = 400
    STATUS_FLOW_STARTED         = 401

    STATUS_DELETE               = 800
    STATUS_DELETE_COMPLETE      = 900


    # GENERIC
    SUCCESS                 = "success"
    LOGIN_ERROR             = "Login Failed"


    # Action
    SA_UPDT                 = "Microsoft.Storage/storageAccounts/write"
    SA_DEL                  = "Microsoft.Storage/storageAccounts/delete"
    VM_UPDT                 = "Microsoft.Compute/virtualMachines/write"
    VM_DEL                  = "Microsoft.Compute/virtualMachines/delete"
    VM_START                = "Microsoft.Compute/virtualMachines/start/action"
    VM_RESTART              = "Microsoft.Compute/virtualMachines/restart/action"
    VM_STOP                 = "Microsoft.Compute/virtualMachines/deallocate/action"

    # Known ignored events
    SA_LIST_KEYS            = "Microsoft.Storage/storageAccounts/listKeys/action"
    PE_CREATE               = "Create or update an private endpoint."
    PE_DELETE               = "Delete an private endpoint."
    PEC_DELETE              = "Delete Private Endpoint Connection"
    SA_CREATE               = "Create/Update Storage Account"
    SA_DELETE               = "Delete Storage Account"
    PE_PROXY                = "Microsoft.Network/privateEndpoints/privateLinkServiceProxies" 

    def __init__(self):
        pass

    @staticmethod
    def insert_to_db_vm(vm, tenantName):
        logger.info("Inserting to DB, VM: {}, tenantName: {}".format(vm["name"], tenantName))
        data = {
                "_id" : vm["resource_id"],
                "customerName" : vm["customerName"],
                "subscriptionId" : vm["sub_id"],
                "subscriptionName" : vm["sub_name"],
                "osinfo" : {
                    "os_class" : vm["os_class"],
                    "name" : "Unknown",
                    "full_name" : vm["os_type"],
                    "os_type" : vm["os_type"],
                },
                "vendorType" : "Azure",
                "azureLocation" : vm["location"],
                "resource_id" : vm["resource_id"],
                "azure_id" : vm["azure_id"],
                "_import_azure_type" : "Virtual Machine",
                "localIp" : vm["privateIp"],
                "_import_subnet" : vm["subnet"],
                "_import_created_time" : vm["createdDate"],
                "systeminfo" : {
                    "additional_tags" : vm["tags"],
                    "availability_zone" : vm["zone"],
                    "region" : vm["location"] ,
                    "model" : vm["size"],
                },
                "publicIp" : vm["publicIp"],
                "account_id" : vm["account_id"],
                "createdDate" : vm["createdDate"],
                "name" : vm["name"],
                "resourceType" : "imported",
                "resourceGroup" : vm["res_group"],
                "endpointType" : "SERVER",
                "network" : vm["network"],
                "secured" : "false",
                "hostname" : vm["name"],
                "_import_cloud_type" : "azure_virtualMachines",
                "_import_vpc" : vm["vnet"],
                "public" : "true",
                "status" : vm["status"],
                "tags" : vm["cm_tags"],
                "interfaces" : vm["interfaces"],
                "lifecycleState" : vm["status"],
                "_import_dns" : {
                    "privateDnsName" : "Default",
                    "publicDnsName" : "Default"
                },
                "tenantId" : vm["tenantIdCm"],
                    "os" : {
                    "edition" : "edition",
                    "version" : "version",
                    "name" : "name",
                },
                "vmSize" : "vmSize",
                "_import_azure_rules" : vm["security_rules"]
        }
        try:
            db.insertIntoDb(data, 'resources', tenantName)
            logger.info("Inserted vm data in resources collections, VM: {}, tenantName: {}".format(vm["name"], tenantName)) 
        except Exception as ex:
            logger.error("Failed Inserted vm data in resources collections, VM: {}, tenantName: {}".format(vm["name"], tenantName)) 
            logger.exception(ex)

    @staticmethod
    def insert_to_db_sa(sa, tenantName):
            logger.info("inside Storage json, SA: {}, tenantName: {}".format(sa["name"], tenantName))
            data = {
                "_id" : sa["resource_id"],
                "resource_id" : sa["resource_id"],
                "customerName" : sa["customerName"],
                "subscriptionId" : sa["sub_id"],
                "subscriptionName" : sa["sub_name"],
                "cloudType" : "Azure",
                "publicIp" : "",
                "cn" : sa['id'],
                "azure_id" : sa["id"],
                "status" : sa["status"],
                "encryption" : sa['encryption'],
                "tenantId" : sa["tenantIdCm"],
                "account_id" : sa["account_id"],
                "endpointType" : "SERVER",
                "connectionType" : "LOCAL",
                "policy_details" : {
                        "policy_delivery" : {
                                "status" : None,
                                "policy_version" : 0,
                                "last_updated_at" :None 
                        }
                },
                "description" : "",
                "tags" : sa["cm_tags"],
                "name" :  sa['name'],
                "resourceType" : "imported",
                "resourceGroup" : sa["resourceGroup"],
                "vendorType" : "Azure",
                "createdDate" : sa['creationTime'],
                "secured" : False,
                "lifecycleState" : sa["provisioningState"],
                "isColormaster" : False,
                "interfaces" : sa["interfaces"],
                "hostname" : sa['name'],
                "edrProtectedStatus" : None,
                "edrSeverity" : None,
                "managementNodeId" : "",
                "resourceGroup" : sa["resourceGroup"],
                "sku" : sa["sku"],
                "azureLocation" : sa["primaryLocation"],
                "network" : sa["network"],
                "newLgm" : True,
                "osInfo" : {},
                "policy_info" : {},
                "localMacaddress" : "",
                "nodeIds" : [ ],
                "infoOverride" : False,
                "systeminfo" : {
                    "additional_tags" : sa["tags"],
                    "region" : sa["primaryLocation"]
                },
                "policy" : {
                        "autocorrect" : False
                },
                "dns" : {
                        "autoConfigure" : True
                },
                "managementNodeId" : "",
                "certificateSerialNumber" : "",
                "cpu" : "" ,
                "isL2CTBManaged" : False,
                "_import_cloud_type" : "azure_storageAccounts",
                "_import_azure_type" : sa["sku"],
                "defaultAccess" : sa["networkRuleSetAction"]
            }
           
            try:
                db.insertIntoDb(data,'resources', tenantName)
                logger.info("Inserted storage data in resources collection, SA: {}, tenantName: {}".format(sa["name"], tenantName)) 
            except Exception as ex:
                logger.error("Failed Insert storage data in resources collection, SA: {}, tenantName: {}".format(sa["name"], tenantName)) 
                logger.exception(ex)
            
    @staticmethod
    def delete_from_db_id(id, tenantName):
        try:
            db.removeFromDb("resources", {"azure_id" : id }, tenantName)
        except Exception as ex:
            logger.error("Failed delete from db, id: {}, tenantName: {}".format(id, tenantName))
            logger.exception(ex)

    # This function adds a 'deleted':True tag before deleting a azure resource from db  
    @staticmethod
    def add_delete_tag_res(id, tenantName):
        try:
            data = {'deleted' :  True}
            db.updateManyDb('resources', data, {"azure_id" : id}, tenantName)
        except Exception as ex:
            logger.error("delete tag addition failed, id: {}, tenantName: {}".format(id, tenantName))
            logger.exception(ex)
            
    @staticmethod
    def delete_from_db_sub(sub_id):
        try:
            db.removeFromDb("resources", {"subscriptionId" : sub_id })
        except Exception as ex:
            logger.error("delete from db sub failed, sub_id: {}".format(sub_id))
            logger.exception(ex)

    # This function adds a 'deleted':True tag before deleting azure resources of a subscription from db  
    @staticmethod
    def add_delete_tag_sub(sub_id):
        try:
            data = {'deleted' :  True}
            db.updateManyDb('resources', data, {"subscriptionId" : sub_id})
        except Exception as ex:
            logger.error("delete tag addition failed for sub id {}".format(sub_id))
            logger.exception(ex)
            
    @staticmethod
    def get_from_db_id(id, tenantName):
        vm = db.retrieveRecordFromDb("resources", {"azure_id": id}, tenantName)
        return vm

    @staticmethod
    def get_sa_list_from_db(tenantName):
        try:
            sa = db.retrieveRecordFromDb("resources", {'_import_cloud_type':"azure_storageAccounts"}, tenantName)
            logger.info("Fetched the SA list from DB, tenantName: {}".format(tenantName))
        except Exception as ex:
            logger.error("get sa list failed, tenantName: {}".format(tenantName))
            logger.exception(ex)

    @staticmethod
    def increment_microsecond(start_time):
        time = start_time.split('.')
        microseconds = int(time[1])
        microseconds = microseconds + 10000
        incremented = ".".join([time[0], str(microseconds)])
        return incremented

    @staticmethod
    def getAzureCustomerAccountFromDB():
        azureAccounts = []
        logger.info("Get all the Azure customer accounts across all tenants")
        records = db.retrieveFromDb('customers', {'cloud_type' : 'Azure'})

        if records.count() == 0:
            logger.info("No Azure customer accounts exists in the DB")
            return azureAccounts

        for record in records:
            azureAccount = {}
            azureAccount["subscription_list"] = record.get("subscription_list") 
            azureAccount["tenant_cm"] = record.get("tenant_name")
            azureAccount["acc_name"] = record.get("customer_name")
            azureAccount["tenant_id"] = record.get("tenant_id")
            azureAccount["service_principal_id"] = record.get("service_principal_id")
            azureAccount["client_id"] = record.get("client_id")
            azureAccount["client_key"] = record.get("client_key")

            logger.info("Found Azure account {} for tenant {}" \
                    .format(azureAccount["acc_name"], azureAccount["tenant_cm"]))
            azureAccounts.append(azureAccount)

        return azureAccounts


    @staticmethod
    def get_event_info(log):
        update_event = collections.namedtuple("update_event",
                                    [   "name",
                                        "id",
                                        "type",
                                        "action"
                                    ])

        id_split = log.resource_id.split('/')
        if len(id_split) <= 7 or \
                id_split[3].lower() != "resourcegroups" or \
                id_split[5].lower() != "providers":
            logger.info("Unknown resource id {}".format(log.resource_id))
            update_event.action = "none"
            return update_event

        update_event.id = log.resource_id
        update_event.name = id_split[8]
        update_event.type = id_split[7]
        update_event.group = id_split[4]
        update_event.action = "none"
        if update_event.type != "virtualMachines" and \
                update_event.type != "storageAccounts" and \
                update_event.type != "privateEndpoints" and \
                update_event.type != "networkSecurityGroups" and \
                update_event.type != "networkInterfaces" and \
                update_event.type != "virtualNetworks":
                logger.info("Ignore resource type {}".format(update_event.type))
                update_event.action = "none"
                return update_event
        logger.debug("localized value is {}".format(log.operation_name.localized_value)) 
        if log.operation_name.localized_value == "List Storage Account Keys" or \
                log.operation_name.localized_value == "Microsoft.Storage/storageAccounts/listKeys/action" :
            return update_event
        if update_event.type == "storageAccounts" and \
                (log.operation_name.localized_value != AzureUtils.SA_CREATE and \
                log.operation_name.localized_value != AzureUtils.PEC_DELETE and \
                log.operation_name.localized_value != AzureUtils.SA_DELETE):
            logger.info("marked action as none for id %s",log.resource_id)
            update_event.action = "none"
        elif update_event.type == "privateEndpoints" and \
                (log.operation_name.localized_value != AzureUtils.PE_DELETE and \
                 log.operation_name.localized_value != AzureUtils.PE_CREATE):
                logger.info("marked action as none for id %s and value %s",log.resource_id,\
                        log.operation_name.localized_value)
                update_event.action = "none"   
        else:
            logger.info("Creating refresh event using resource id {}".format(log.resource_id))
            logger.debug("log read was {}".format(log)) 
            update_event.action = "refresh"

        return update_event

    @staticmethod
    def login(customerAccount):
        lock.acquire()
        status = AzureUtils.SUCCESS
        
        logger.info("Login to App Id: {}".format(customerAccount.client_id))
        start = time.time()
        try:
            customerAccount.credentials = ServicePrincipalCredentials(
                                        client_id = customerAccount.client_id,
                                        secret = customerAccount.key,
                                        tenant = customerAccount.tenant_id) 
            logger.info("Login successful for tenant {}".format(customerAccount.tenant_id))               
        except Exception as ex:
            logger.exception(ex)
            status = str(ex)
            
        except:
            status = "Login failed for uknown reason"
            logger.error(status)

        done = time.time()
        elapsed = done - start
        logger.info("Time Taken for login {} seconds".format(elapsed))
        lock.release()
        return status
     
    @staticmethod
    def validate_role_assignments(customerAccount, subscription_id):
        try:
            logger.info("Validating role assignments for customer {}, sub id {}".format(customerAccount.customerName, subscription_id))
            client = AuthorizationManagementClient(customerAccount.credentials, subscription_id)
            roles = client.role_assignments.list()
            
            reader_access = False
            reader_and_data_access = False
            
            for role in roles:
                
                if role.principal_id == customerAccount.service_principal_id:
                    
                    if role.role_definition_id == AzureUtils.get_reader_role_definition_id(subscription_id):
                        reader_access = True
                    
                    if role.role_definition_id == AzureUtils.get_reader_and_data_role_definition_id(subscription_id):
                        reader_and_data_access = True
                
            if reader_access and reader_and_data_access:
                logger.info("Role assignments Validated for customer {}, sub id {}".format(customerAccount.customerName, subscription_id))
                return True
            else: 
                logger.error("Role assignments Incorrect for customer {}, sub id {}".format(customerAccount.customerName, subscription_id))
                return False
            
        except Exception as ex:
            logger.error("Error in Validating Role assignment for customer {}, sub id {}".format(customerAccount.customerName, subscription_id))
            logger.exception(ex)
            return False
          
    @staticmethod
    def get_customer_accounts(tenantId=None):
        from ct_azure.init.azure_cloud_init import getAzureCustomerAccountList
        customer_list = []
        for customer in getAzureCustomerAccountList():
            if customer.tenantIdCm == tenantId:
                customer_list.append(customer)
        if len(customer_list) == 0:
            logger.error("No customer exists on tenantid {}" \
                                .format(tenantId))
        logger.info("There are total {} accounts".format(len(customer_list)))
        return customer_list

    @staticmethod
    def get_subscription(subscription_id):
        from ct_azure.init.azure_cloud_init import getAzureCustomerAccountList
        for customer in getAzureCustomerAccountList():
            if len(customer.subscriptionList):
                for sub in customer.tenant.subscriptions:
                    if sub.subscription_id == subscription_id:
                        return sub
        return None

    @staticmethod
    def get_resource_group(sub_id, group_name):
        sub = AzureUtils.get_subscription(sub_id)
        if sub:
            for group in sub.res_group_list:
                if group.name == group_name:
                    return group
        return None
    
    @staticmethod
    def get_sa_list_from_pe_cache(sub_id, pe):
        sa_list = []
        sub = AzureUtils.get_subscription(sub_id)
        if sub:
            for group in sub.res_group_list:
                for sa in group.storageAccounts:
                    for ref in sa.pe_list:
                        if ref.name == pe:
                            logger.info("found %s linked to %s", sa.azure_id, pe)
                            sa_list.append(sa.azure_id)
        #this will be None if event is PE addition
        return sa_list
    
    #get sa name form /subscriptions/320fa430-abaa-45a1-85bf-47dd8e93a35b/resourceGroups/Kiran_Testing_RG/providers/Microsoft.Storage/storageAccounts/linkedprivatedkiran
    @staticmethod
    def get_sa_list_from_pe(group, pe):
        res_list = []
        azure_pe = AzureUtils.get_private_endpoint(group, pe)
        if azure_pe == None:
            logger.info("Unable to find pe with name %s in azure",pe)
            return res_list
        for conn in azure_pe.private_link_service_connections:
            if "storageAccounts" in conn.private_link_service_id:
                logger.info("found %s linked %s", conn.private_link_service_id, pe)
                res_list.append(conn.private_link_service_id)
        return res_list

    @staticmethod
    def get_vm_list_from_nsg(sub_id, nsg):
        vm_list = []
        sub = AzureUtils.get_subscription(sub_id)
        if sub:
            for group in sub.res_group_list:
                for vm in group.virtualMachines:
                    for intf in vm.interfaces:
                        if intf.nsg:
                            if intf.nsg.name == nsg:
                                vm_list.append(vm.azure_id)
                            for subnet in intf.subnets:
                                logger.info(subnet.name)
                                if subnet.nsg:
                                    logger.info(subnet.nsg.name)
                                    if subnet.nsg.name == nsg:
                                        vm_list.append(vm.azure_id)
        return vm_list

    @staticmethod
    def get_vm_list_from_vnet(sub_id, vnet):
        vm_list = []
        sub = AzureUtils.get_subscription(sub_id)
        if sub:
            for group in sub.res_group_list:
                for vm in group.virtualMachines:
                    for intf in vm.interfaces:
                        for subnet in intf.subnets:
                            if subnet.vnet.name == vnet:
                                vm_list.append(vm.azure_id)
        return vm_list

    @staticmethod
    def get_vm_from_intf(sub_id, intf):
        vm_list = []
        sub = AzureUtils.get_subscription(sub_id)
        if sub:
            for group in sub.res_group_list:
                for vm in group.virtualMachines:
                    for this_intf in vm.interfaces:
                        if this_intf.name == intf:
                            vm_list.append(vm.azure_id)
        return vm_list

    @staticmethod
    # NSG carries two references one in interface and other in subnet
    # Deliberately skipping interface references because interfaces are removed when VMs are refreshed.
    # During VM refresh, vnets are not touched leading to them pointing to old NSG
    def delete_nsg_reference(sub_id, nsg_name):
        logger.info("Delete NSG references..")
        sub = AzureUtils.get_subscription(sub_id)
        vnet_list = []
        vnet_found = False

        if sub:
            for group in sub.res_group_list:
                vnet_list = []
                for vnet in group.virtualNetworks:
                    vnet_found = False
                    for subnet in vnet.subnetList:
                        if subnet.nsg:
                            if subnet.nsg.name == nsg_name:
                                vnet_found = True
                                break
                    if vnet_found:
                        vnet_list.append(vnet)

                if len(vnet_list):
                    for vnet in vnet_list:
                        logger.info("Clearing NSG reference for vnet {}, sub_id: {}".format(vnet.name, sub_id))
                        group.delete_virtual_network(vnet)

    @staticmethod
    def get_storage_account(group, name):
        storageClient = group.subscription_info.storageClient
        azure_sa = None
        try:
            azure_sa = storageClient.storage_accounts.get_properties(group.name, name)
        except:
            logger.error("Storage account {} is not found, group: {}".format(name, group.name))
        return azure_sa 

    @staticmethod
    def get_storage_account_key(group, name):
        storageClient = group.subscription_info.storageClient
        key = ''
        try:
            storage_keys = storageClient.storage_accounts.list_keys(group.name, name)
            storage_keys = {v.key_name: v.value for v in storage_keys.keys}
            key = format(storage_keys['key2'])
        except:
            logger.error("Storage account {} is not found, group: {}".format(name, group.name))
        return key

    @staticmethod
    def get_virtual_machine(group, name):
        computeClient = group.subscription_info.computeClient
        azure_vm = None
        try:
            azure_vm = computeClient.virtual_machines.get(group.name, name)
        except:
            logger.error("Virtual Machine {} is not found, group: {}".format(name, group.name))
        return azure_vm

    @staticmethod
    def get_virtual_machine_list(group):
        computeClient = group.subscription_info.computeClient
        azure_vm_list  = None
        try:
            azure_vm_list = computeClient.virtual_machines.list(group.name)
        except:
            logger.error("Virtual Machine list {} is not found".format(group.name))
        return azure_vm_list

    @staticmethod
    def get_virtual_machine_list_all(client):
        azure_vm_list  = None
        try:
            azure_vm_list = client.virtual_machines.list_all()
        except:
            logger.error("Virtual Machine lists is not found")
        return azure_vm_list

    @staticmethod
    def get_storage_account_list_all(client):
        azure_sa_list = None
        try:
            azure_sa_list = client.storage_accounts.list()
        except:
            logger.error("Storage accounts is not found")
        return azure_sa_list 

    @staticmethod
    def get_storage_account_list(group):
        storageClient = group.subscription_info.storageClient
        azure_sa_list = None
        try:
            azure_sa_list = storageClient.storage_accounts.list_by_resource_group(group.name)
        except:
            logger.error("Storage accounts {} is not found".format(group.name))
        return azure_sa_list 

    @staticmethod
    def get_vnet_list(group):
        networkClient = group.subscription_info.networkClient
        azure_vnet_list = None
        try:
            azure_vnet_list= networkClient.virtual_networks.list(group.name)
        except:
            logger.error("Vnets list {} not found".format(group.name))
        return azure_vnet_list


    @staticmethod
    def get_private_endpoint(group, name):
        networkClient = group.subscription_info.networkClient
        azure_pe_list = []
        try:
            #azure.mgmt.storage.v2019_06_01.models._models.PrivateEndpointConnection
            azure_pe_list = networkClient.private_endpoints.list(group.name)
            for pe in azure_pe_list:
                if pe.name == name:
                    return pe
        except Exception as e:
            logger.error(e)
        return None

    @staticmethod
    def get_private_endpoint_list(group):
        networkClient = group.subscription_info.networkClient
        azure_pe_list = None
        try:
            #azure.mgmt.storage.v2019_06_01.models._models.PrivateEndpointConnection
            azure_pe_list = networkClient.private_endpoints.list(group.name)
        except Exception as e:
            logger.error(e)
        return azure_pe_list

    
    @staticmethod
    def get_nsg_list(group):
        networkClient = group.subscription_info.networkClient
        azure_nsg_list = None
        try:
            azure_nsg_list = networkClient.network_security_groups.list(group.name)
        except Exception as e:
            logger.error("NSG list {} not found".format(group.name))
            logger.exception(e)
        return azure_nsg_list

    @staticmethod
    def get_interface(group, name):
        networkClient = group.subscription_info.networkClient
        azure_intf = None
        try:
            azure_intf = networkClient.network_interfaces.get(group.name, name)
        except Exception as e:
            logger.error(e)
        return azure_intf

    @staticmethod
    def get_interface_list(group):
        networkClient = group.subscription_info.networkClient
        azure_intf_list = None
        try:
            azure_intf_list = networkClient.network_interfaces.list(group.name)
        except Exception as e:
            logger.error("Interface list {} not found".format(group.name))
            logger.exception(e)
        return azure_intf_list

    @staticmethod
    def get_group_from_id(account, id):
        return account.tenant.get_resource_group_from_id(id)

    @staticmethod
    def get_vnet(group, name):
        networkClient = group.subscription_info.networkClient
        azure_vnet = None
        try:
            azure_vnet = networkClient.virtual_networks.get(group.name, name)
        except:
            logger.error("Virtual Netowrk {} not found".format(name))
        return azure_vnet

    @staticmethod
    def valid_subscription(sub_id, credentials):
        sub_name = ""
        try:
            subscriptionClient = SubscriptionClient(credentials)
            sub = subscriptionClient.subscriptions.get(sub_id)
            sub_name = sub.display_name
        except CloudError as ex:
            logger.error("Invalid subscription {}".format(sub_id))
            logger.exception(ex)
            return sub_name, False
        
        if sub.state != "Enabled":
            logger.error("Subscription {} found but not enabled".format(sub_id))
            return sub_name, False
        
        return sub_name, True


    @staticmethod
    def get_vm_from_mac(account,  mac_address):
        vm = account.tenant.get_resource_id_from_mac(mac_address)
        if vm == None:
            logger.error("Failed to find VM for mac {}".format(mac_address))
        return vm

    @staticmethod
    def get_timestamp_from_utc(utctime):
        dt = parse(utctime)
        tsutc = int(dt.strftime("%s"))
        epochtime = '1970-01-01T00:00:00Z'
        dtepoch = parse(epochtime)
        tsepoch = int(dtepoch.strftime("%s"))
        return tsutc-tsepoch

    # Reader role definition id = acdd72a7-3385-48ef-bd42-f606fba81ae7
    @staticmethod
    def get_reader_role_definition_id(subscription_id):
        return "/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7".format(subscription_id)
    
    # Read and Data Access definition id = c12c1c16-33a1-487b-954d-41c89c60f349
    @staticmethod
    def get_reader_and_data_role_definition_id(subscription_id):
        return "/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions/c12c1c16-33a1-487b-954d-41c89c60f349".format(subscription_id)
