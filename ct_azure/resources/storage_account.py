from ct_azure.utils.utils import AzureUtils
from ct_azure.resources.private_endpoint import PrivateEndpoint
from ct_azure.utils.net_utils import AzureNetUtils
from ct_azure.utils.utils import ctlogger
import logging
import hashlib
import socket
logger = logging.getLogger('cloud_monitor.StorageAccount')

#https://docs.microsoft.com/en-us/python/api/azure-storage-common/azure.storage.common.storageclient.storageclient?view=azure-python-previous
class StorageAccount:
    #constants
    LOCAL_IP = "0.0.0.0"
    def __init__(self, azure_storage_acc, subsciption_info, customer_account, storageKey=None):
        self.account = azure_storage_acc
        self.subsciption_info = subsciption_info
        self.customer_account = customer_account
        self.name = self.account.name
        self.tenantName = customer_account.tenantName
        self.key = storageKey
        self.azure_id = self.account.id
        self.resource_id = hashlib.md5(str(self.azure_id).encode()).hexdigest()
        self.cm_tag_list = self.get_cm_tags()
        self.interfaces = []
        self.uri = self.name+".blob.core.windows.net"
        self.local_ip = self.LOCAL_IP
        self.get_local_ip()
        self.pe_list = []
        self.logger = ctlogger(logger, {'custname' : self.customer_account.customerName \
                + "-" + self.customer_account.tenantName})

    def get_local_ip(self):
        try:
            self.local_ip = socket.gethostbyname(self.uri)
        except:
            self.local_ip = self.LOCAL_IP
    
    #add pe to pelist and pelist at group level if not already present
    def discover_pe(self):
        self.pe_list = []
        self.logger.info("Discovering pe")
        #reference is object of azure.mgmt.storage.v2019_06_01.models._models.PrivateEndpointConnection
        #/subscriptions/320fa430-abaa-45a1-85bf-47dd8e93a35b/resourceGroups/VHResourceGroup/providers/
        #/Microsoft.Storage/storageAccounts/vhstorageacceast/privateEndpointConnections/vhstorageacceast.115e19c8-901a-4442-bffa-2eb65a10722c
        for reference in self.account.private_endpoint_connections:
            group_obj = AzureUtils.get_group_from_id(self.customer_account, reference.id)
            assert(group_obj != None)
            idsplit = reference.private_endpoint.id.split('/')
            group = idsplit[4]
            #/subscriptions/320fa430-abaa-45a1-85bf-47dd8e93a35b/resourceGroups/VHResourceGroup/providers/Microsoft.Network/privateEndpoints/VHPrivateEP'
            name = idsplit[8] 
            self.logger.info("Discovering pe %s",name)
            pe = group_obj.get_private_endpoint(name)
            if pe != None:
                group_obj.delete_pe(pe)
            #<azure.mgmt.network.v2020_04_01.models._models.PrivateEndpoint
            azure_pe = self.subsciption_info.networkClient.private_endpoints.get(group, name)
            pe = PrivateEndpoint(azure_pe, self.subsciption_info, self.customer_account)
            pe.load_private_endpoint()
            group_obj.add_private_endpoint(pe)
            self.pe_list.append(pe)

    def register_storage_account(self):
        self.logger.info("Registering storage account {}".format(self.name))
        ct_sa = {}
        self.discover_pe()
        logger.info("Discovered pe for {}".format(self.name))
        self.populate_sa_data(ct_sa)

        if (AzureUtils.get_from_db_id(ct_sa["id"], self.tenantName) != None):
            self.logger.info("Deleting sa {}".format(self.name))
            AzureUtils.add_delete_tag_res(ct_sa["id"], self.tenantName)
            AzureUtils.delete_from_db_id(ct_sa["id"], self.tenantName)
        AzureUtils.insert_to_db_sa(ct_sa, self.tenantName)

    def update_azure_sa(self, azure_sa):
        self.account = azure_sa

    def get_resource_id(self):
        return self.resource_id

    def get_azure_id(self):
        return self.azure_id
    
    def get_cm_tags(self):
        sa = AzureUtils.get_from_db_id(self.get_azure_id(), self.tenantName)
        if sa == None or 'tags' not in sa or sa['tags'] == None:
            return []
        else:
            return sa["tags"]

    def unregister_storage_account(self):
        sa = AzureUtils.get_from_db_id(self.get_azure_id(), self.tenantName)
        self.logger.info("Unregister sa {}".format(self.get_azure_id()))
        if sa != None:
            self.cm_tag_list = sa["tags"]
            self.logger.info("Deleting sa {}".format(self.name))
            AzureUtils.add_delete_tag_res(self.get_azure_id(), self.tenantName)
            AzureUtils.delete_from_db_id(self.get_azure_id(), self.tenantName)
            
        if len(self.pe_list):
            for pe in self.pe_list:
                self.pe_list.remove(pe)
                pe.unregister_private_endpoint()

        self.interfaces = []

    def get_interface_list(self):
        s = {
             "interface" : self.name,
             "v6Addr" : "",
             "v4Addr" : self.local_ip,
             "netmask" : "255.255.255.255",
             "macaddress" : "00:00:00:00:00:00",
             "status" : "up",
             "ip" : [self.local_ip]
             }
        self.interfaces.append(s)
        if len(self.pe_list) == 0:
            return self.interfaces
        intf_list = [] 
        for pe in self.pe_list:
            for intf in pe.interface_list:
                intf_list.append(intf)

        for intf in intf_list:
            #TBD handling Ipv6 cases
            if len(intf.public_ip):
                for ipconfig in intf.public_ip:
                    if ipconfig["ip_address"] == None:
                        continue
                    s = {
                        "interface" : intf.name,
                        "v4Addr": ipconfig["ip_address"],
                        "v6Addr" : "",
                        "netmask" : ipconfig["netmask"],
                        "macaddress" : intf.mac_address,
                        "status" : "up",
                        "ip" : [ipconfig["ip_address"]]
                        }
                    
                    self.interfaces.append(s)
            if len(intf.private_ip):
                for ipconfig in intf.private_ip:
                    if ipconfig["ip_address"] == None:
                        continue
                    s = {
                        "interface" : intf.name,
                        "v4Addr": ipconfig["ip_address"],
                        "v6Addr" : "",
                        "netmask" : ipconfig["netmask"], 
                        "macaddress" : intf.mac_address,
                        "status" : "up",
                        "ip" : [ipconfig["ip_address"]]
                        }
                    self.interfaces.append(s)
        return self.interfaces

    def get_network_list(self):
         network_list = []
         for intf in self.interfaces:
            s = {
                "ip": intf["v4Addr"],
                "netmask" : intf["netmask"],
                "ipInt" : AzureNetUtils.ip_to_int(intf["v4Addr"])
                }
            network_list.append(s)

         return network_list
     
    def populate_sa_data(self, ct_sa):
        ct_sa["name"] = self.name
        ct_sa["sub_id"] = self.subsciption_info.Id
        ct_sa["sub_name"] = self.subsciption_info.name
        ct_sa["customerName"] = self.customer_account.customerName
        ct_sa["id"] = self.get_azure_id()
        ct_sa["resource_id"] = self.get_resource_id()
        ct_sa["status"] = self.account.status_of_primary
        ct_sa["encryption"] = self.account.encryption.services.blob.enabled
        ct_sa["tenantIdCm"] = self.customer_account.tenantIdCm
        ct_sa["account_id"] = self.customer_account.tenant_id
        ct_sa["interfaces"] = self.get_interface_list()
        ct_sa["tags"] = self.get_azure_tags(False)
        ct_sa["cm_tags"] = self.get_azure_tags(True)
        ct_sa["resourceGroup"] =  self.account.id.split('/')[4]
        ct_sa["sku"] = self.account.sku.name
        ct_sa["creationTime"] = self.account.creation_time
        ct_sa["provisioningState"] = self.account.provisioning_state
        ct_sa["primaryLocation"] = self.account.primary_location.capitalize()
        ct_sa["networkRuleSetAction"] = self.account.network_rule_set.default_action
        ct_sa["network"] = self.get_network_list()

    def get_azure_tags(self, cm_tags):
        tag_list = []
        policy_tags = ['application','environment','location','roles','service']

        if self.account.tags:
            for tag in self.account.tags:
                t = {
                    "actualKey"   : tag,
                    "lowerKey"    : tag.lower(),
                    "actualValue" : self.account.tags[tag],
                    "lowerValue"  : self.account.tags[tag].lower(),
                    "actualValueV1" : [],
                    "lowerValueV1"  : []
                    }

                if t['lowerKey'] in policy_tags:
                    t["actualKey"] = tag.title()
                    t["actualValueV1"].append(self.account.tags[tag])
                    t["lowerValueV1"].append(self.account.tags[tag].lower())
                    if len(self.cm_tag_list):
                        tag = next((tagi for tagi in self.cm_tag_list if (tagi["lowerKey"] ==  t["lowerKey"] \
                                and tagi["lowerValue"] == t["lowerValue"])), None)
                        if tag == None:
                            self.cm_tag_list.append(t)
                    else:
                        self.cm_tag_list.append(t)
                else:
                    tag_list.append(t)

        if cm_tags:
            return self.cm_tag_list
        else:
            return tag_list

