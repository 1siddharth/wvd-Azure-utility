from ct_azure.tenant.tenant import Tenant
from ct_azure.utils.utils import ctlogger
import logging

logger = logging.getLogger('cloud_monitor.account')

# An instance one customer account
# This is the root of the hierarchy
#                    Account
#         Sub1                    Sub2           
#    Grp1      Grp2        Grp1           Grp2
#  Res1 Res2   Res1       Res1 Res2      Res1 Res2 Res3
#
#  One Account has One Azure Tenant
#  One Tenant  has One or more subscriptions
#  One Subsription has One or more Resource groups
#  One Resource Group has multiple resources
#  https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/overview
class AzureCustomerAccount(object) :

    def __init__(self, customername, tenantid, servicePrincipalId, clientid, key, subscriptionlist, \
                            tenantIdCm, tenantName) :
        self.logger = ctlogger(logger, {'custname' : customername \
                                                + "-" + tenantName})
        self.logger.info("azureCustomerAccount initialization")
        self.logger.info("Customer Name : {}".format(customername))
        self.logger.info("Azure Tenant : {}".format(tenantid))
        self.logger.info("ClientId : {}".format(clientid))
        self.logger.info("Service Principal Id : {}".format(servicePrincipalId))
        self.logger.info("CM : {}".format(tenantIdCm))
        self.customerName = customername
        self.tenant_id = tenantid
        self.client_id = clientid
        self.service_principal_id = servicePrincipalId
        self.key = key
        self.tenant = None
        self.credentials = None
        self.subscriptionList = subscriptionlist
        self.tenantIdCm = tenantIdCm
        self.tenantName = tenantName
        self.logger.info("command executer initialised in customer account")

    def do_discovery(self):
        self.tenant = Tenant(self)
        self.tenant.do_discovery()
