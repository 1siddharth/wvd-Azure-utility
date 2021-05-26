import logging
from ct_azure.resources.subnet import Subnet
from ct_azure.utils.utils import ctlogger

logger = logging.getLogger("cloud_monitor.VirtualNetwork")

# Virtual Network
# https://docs.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.v2020_03_01.models.virtualnetwork?view=azure-python

class VirtualNetwork:

    def __init__(self, vnet, subscription_info, customerAccount):
        self.vnet = vnet
        self.subscription_info = subscription_info
        self.customerAccount = customerAccount
        self.logger = ctlogger(logger, {'custname' : self.customerAccount.customerName \
                                                + "-" + self.customerAccount.tenantName})
        self.name = vnet.name
        self.subnetList = []

    def load_subnets(self):
        for azure_subnet in self.vnet.subnets:
            subnet = Subnet(azure_subnet, self.vnet, self.subscription_info, self.customerAccount)
            subnet.load_subnet()
            self.subnetList.append(subnet)

    def load_virtual_network(self):
        self.logger.info("Loading virtual network {}".format(self.name))
        self.id = str(self.vnet.id)
        self.location = str(self.vnet.location)
        self.provisioning_state = str(self.vnet.provisioning_state)
        self.load_subnets()
