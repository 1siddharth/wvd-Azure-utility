from ct_azure.resources.network_interface import NetworkInterface
from ct_azure.utils.utils import AzureUtils
from ct_azure.utils.utils import ctlogger
import logging
logger = logging.getLogger("cloud_monitor.PrivateEndpoint")

"""
PrivateEndpoint
https://docs.microsoft.com/en-us/python/api/azure-mgmt-storage/
azure.mgmt.storage.v2019_06_01.models.privateendpoint?view=azure-python
"""
class PrivateEndpoint:
    def __init__(self, pe, subscription_info, customerAccount):
        self.pe = pe
        self.subscription_info = subscription_info
        self.customerAccount = customerAccount
        self.networkClient = self.subscription_info.networkClient
        self.name = pe.name
        self.group_name = self.pe.id.split('/')[4]
        self.azure_interface_list = pe.network_interfaces
        self.interface_list = []
        self.location = pe.location
        self.id = pe.id
        self.azure_id = pe.id
        self.logger = ctlogger(logger, {'custname' : self.customerAccount.customerName \
                                           + "-" +self.customerAccount.tenantName})
    
    def load_private_endpoint(self):
        self.logger.info("Loading private endpoint {}".format(self.name))
        #<azure.mgmt.network.v2020_04_01.models._models.NetworkInterface object
        for azure_interface in self.azure_interface_list:
            group_obj = AzureUtils.get_group_from_id(self.customerAccount, azure_interface.id)
            id_split = azure_interface.id.split('/')
            intf_azure = AzureUtils.get_interface(group_obj,id_split[8])
            interface = NetworkInterface(intf_azure, self.subscription_info, self.customerAccount)
            interface.load_network_interface()
            self.interface_list.append(interface)
    
    def unregister_private_endpoint(self):
        self.logger.info("Unregistering private endpoint {}".format(self.name))
        for intf in self.interface_list:
            group_obj = AzureUtils.get_group_from_id(self.customerAccount, intf.id)
            if group_obj:
                group_obj.delete_network_interface(intf)
                group_obj.delete_pe(self)
                self.logger.info("deleted interface and pe %s",self.name)
