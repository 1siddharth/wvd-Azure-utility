from azure.common.credentials import ServicePrincipalCredentials
from ct_azure.subscription.subscription import Subscription
from ct_azure.utils.utils import AzureUtils, ctlogger
import threading
import logging
import Queue
import time

logger = logging.getLogger('cloud_monitor.Tenant')

"""
A class which implements a Azure Tenant.
A Tenant can have one ore more subscriptions.
An account have only one subscription
"""
class Tenant:

    # constants
    ACTION_CLEANUP      = 2 # cleanup a tenant

    def __init__(self, azureCustAcc):
        self.customerAccount = azureCustAcc
        self.logger = ctlogger(logger, {'custname' : self.customerAccount.customerName \
                                                + "-" + self.customerAccount.tenantName})
        self.logger.info("Tenant initialization id:  {}".format(azureCustAcc.tenant_id))
        self.subscriptions = []
        self.status = AzureUtils.STATUS_LOGIN
        self.error = ""
        self.warning = ""
        self.event_handler_q = Queue.PriorityQueue()
        self.service_principal_q = Queue.PriorityQueue()
        self.event_thread = threading.Thread(target=self.event_handler)
        self.service_principal_thread = threading.Thread(target=self.monitor_service_principal)
        self.event_thread.start()
        self.service_principal_thread.start()

        for subscription_id in self.customerAccount.subscriptionList:
            self.logger.info("Adding the Subscription Id {}".format(subscription_id))
            this_subscription = Subscription(subscription_id, self.customerAccount)
            self.subscriptions.append(this_subscription)

    def event_handler(self):
        while True:
            item = self.event_handler_q.get()
            self.logger.info("event handler cleanup initiated")
            if (item == self.ACTION_CLEANUP):
                self.service_principal_q.put(item)
                if self.service_principal_thread.is_alive():
                    self.service_principal_thread.join(60)
                break
            
        self.status = AzureUtils.STATUS_DELETE_COMPLETE
        self.logger.info("Exiting the event handler thread of tenant {}".format(self.customerAccount.tenant_id))

    def monitor_service_principal(self):
        self.logger.info("Inside monitor service principal thread")

        while True:    
            try:
                item = self.service_principal_q.get(timeout=300)
                if (item == self.ACTION_CLEANUP):
                    self.logger.info("Service principal cleanup initiated")
                    break
            except Queue.Empty:
                pass

            self.logger.info("Validating service principal credentials")

            if self.validate_service_principal():
                self.status = AzureUtils.STATUS_LOGIN_COMPLETED
            else:
                self.status = AzureUtils.STATUS_LOGIN_FAILED

    def validate_service_principal(self):
        login_status = AzureUtils.login(self.customerAccount)

        if login_status != AzureUtils.SUCCESS:
            self.logger.info("Failed Azure service principal validation")
            self.status = AzureUtils.STATUS_LOGIN_FAILED
            self.error = login_status
            return False
        else:
            self.logger.info("Azure service principal validated")
            self.status = AzureUtils.STATUS_LOGIN_COMPLETED
            self.error = ""  # No error is shown in case of successful service principal validation
            return True

    def do_discovery(self):
        if self.validate_service_principal():
            for subscription in self.subscriptions:
                self.logger.info("Discover Subscription Id {}".format(subscription.subscription_id))
                subscription.enqueue_action(Subscription.ACTION_DISCOVER_SUB)

    def do_cleanup(self):
        self.logger.info("action cleanup {}".format(self.ACTION_CLEANUP))
        self.event_handler_q.put(self.ACTION_CLEANUP)

        for subscription in self.subscriptions:
            self.logger.info("Enqueue cleanup action for subscription {}" \
                                .format(subscription.subscription_id))
            subscription.enqueue_action(Subscription.ACTION_CLEANUP)

        self.status = AzureUtils.STATUS_DELETE    

    def get_status(self):
        sub_status = ""
        for subscription in self.subscriptions:
            sub_status = subscription.status
            break

        self.logger.info("Tenant {} Status : {}".format(self.customerAccount.tenant_id, self.status))
        self.logger.info("Subscription {} Status : {}".format(self.customerAccount.tenant_id, sub_status))

        if self.status == AzureUtils.STATUS_LOGIN_FAILED or sub_status == AzureUtils.STATUS_LOGIN_FAILED:
            return "Account Login Failed"
        elif sub_status == AzureUtils.STATUS_LOGIN:
            return "Account Check In Progress"
        elif sub_status == AzureUtils.STATUS_LOGIN_COMPLETED:
            return "Resource Discovery In Progress"
        elif sub_status == AzureUtils.STATUS_DISCOVERY_COMPLETED or \
             sub_status == AzureUtils.STATUS_MONITOR_STARTED or \
             sub_status == AzureUtils.STATUS_FLOW_STARTED:
            return "Account Monitoring In Progress"
        elif sub_status == AzureUtils.STATUS_DELETE:
            return "Account Deletion In Progress"
        elif sub_status == AzureUtils.STATUS_DELETE_COMPLETE:
            return "Account Deleted"
        else:
            return "Monitoring Failed"

    def get_error(self):
        error_list = []
        if self.error:
            error_list.append(self.error)

        for subscription in self.subscriptions:
            if subscription.error:
                error_list.append(subscription.error)
                if len(error_list) >= 5:
                    break

        return error_list

    def get_warning(self):
        warning_list = []
        if self.warning:
            warning_list.append(self.warning)

        for subscription in self.subscriptions:
            if subscription.warning != "":
                warning_list.append(subscription.warning);
                if len(warning_list) >= 5:
                    break;
        return warning_list;

    def get_discovery_status(self):
        for subscription in self.subscriptions:
            sub_status = subscription.status
            break

        if self.status == AzureUtils.STATUS_LOGIN_FAILED:
            return False

        if sub_status >= AzureUtils.STATUS_DISCOVERY_COMPLETED:
            return True

        return False

    def get_monitoring_status(self):
        for subscription in self.subscriptions:
            sub_status = subscription.status
            break

        if self.status == AzureUtils.STATUS_LOGIN_FAILED:
            return False

        if sub_status >= AzureUtils.STATUS_MONITOR_STARTED:
            return True

        return False


    def get_flow_status(self):
        for subscription in self.subscriptions:
            sub_status = subscription.status
            break

        if self.status == AzureUtils.STATUS_LOGIN_FAILED:
            return False

        if sub_status >= AzureUtils.STATUS_FLOW_STARTED:
            return True

        return False


    def get_policy_status(self):
        return False

    def get_susbscription_ids(self):
        return list(x.subscription_id for x in self.subscriptions)

    def get_vnets(self):
        vnets = []
        for subscription in self.subscriptions:
            for groups in subscription.res_group_list:
                for vnet in groups.virtualNetworks:
                    self.logger.info("Append vent {}".format(vnet.name))
                    vnets.append(vnet)
        return vnets

    def get_sas(self):
        sas= []
        for subscription in self.subscriptions:
            for groups in subscription.res_group_list:
                for sa in groups.storageAccounts:
                    sas.append(sa)
        return sas

    def get_resource_group_from_id(self, id):
        id_parts = id.split("/")
        if len(id_parts) < 5:
            return None

        sub = id_parts[2]
        group = id_parts[4]

        this_sub = next((this_sub for this_sub in self.subscriptions if this_sub.subscription_id == sub), None)
        if this_sub == None:
            return None 

        this_group = next((this_group for this_group in this_sub.res_group_list if this_group.name == group), None)
        return this_group 

    def get_vnet_id(self):
        vnet_ids = []
        for subscription in self.subscriptions:
            for groups in subscription.res_group_list:
                for vnet in groups.virtualNetworks:
                    vnet_ids.append(vnet.id)
        return vnet_ids
    
    # Handlw two vnets having same name across resource groups or subscriptions
    def get_resource_id_from_vnet(self, vnet):
        vnet = vnet.split('/')[8]
        resource_ids = []
        for subscription in self.subscriptions:
            self.logger.info("Get resources of subscription {}".format(subscription.subscription_id))
            for groups in subscription.res_group_list:
                for vm in groups.virtualMachines:
                    for interface in vm.interfaces:
                        if vnet == interface.get_vnet():
                            r = { 'name' : vm.name,
                                  'resourceid' : vm.resource_id
                                }
                            resource_ids.append(r)
        return resource_ids

    def get_resource_id_from_mac(self, mac_address):
        for subscription in self.subscriptions:
            for groups in subscription.res_group_list:
                for vm in groups.virtualMachines:
                    for interface in vm.interfaces:
                        if mac_address == interface.mac_address:
                            return vm.resource_id
        return None
