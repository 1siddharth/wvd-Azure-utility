import logging
from ct_azure.utils.utils import AzureUtils, ctlogger

logger = logging.getLogger("cloud_monitor.disk")

# Disk
# https://docs.microsoft.com/en-us/python/api/azure-mgmt-compute/azure.mgmt.compute.v2019_11_01.models.disk?view=azure-python
#

class Disk():

    def __init__(self, disk, subscription_info, customerAccount):
        self.logger = ctlogger(logger, {'custname' : customerAccount.customerName \
                                                + "-" + customerAccount.tenantName})
        self.disk = disk
        self.name = disk.name
        self.subscription_info = subscription_info
        self.customerAccount = customerAccount
        self.logger.info("Disk Initialized: {}".format(self.name))

    def get_state(self):
        return self.disk.disk_state

    def get_size(self):
        return self.disk.disk_size_gb

    def get_creation_time(self):
        return self.disk.time_created
