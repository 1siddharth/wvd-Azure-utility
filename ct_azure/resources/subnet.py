from ct_azure.resources.network_security_group import NetworkSecurityGroup
from ct_azure.utils.utils import AzureUtils, ctlogger
import logging

logger = logging.getLogger("cloud_monitor.subnet")


# Subnet
# https://docs.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.v2020_03_01.models.subnet?view=azure-python
class Subnet:

    def __init__(self, subnet, vnet, subscription_info, customerAccount):
        self.subnet = subnet
        self.name = subnet.name
        self.vnet = vnet
        self.subscription_info = subscription_info
        self.customerAccount = customerAccount
        self.logger = ctlogger(logger, {'custname' : self.customerAccount.customerName \
                                                + "-" + self.customerAccount.tenantName})
        self.networkClient = self.subscription_info.networkClient
        self.nsg = None

    def load_subnet(self):
        self.logger.info("Loading subnet {}".format(self.name))
        azure_nsg = self.subnet.network_security_group
        if azure_nsg:
            group = AzureUtils.get_group_from_id(self.customerAccount, azure_nsg.id)
            assert(group != None)

            nsg_parts = azure_nsg.id.split("/")
            nsg_name = nsg_parts[8]
            nsg = group.get_security_group(nsg_name)
            if nsg == None:
                azure_nsg = self.networkClient.network_security_groups.get(group.name, nsg_name)
                nsg = NetworkSecurityGroup(azure_nsg, self.subscription_info, self.customerAccount)
                group.add_security_group(nsg)

            self.nsg = nsg
