from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.monitor import MonitorManagementClient

from ct_azure.resource_group.resource_group import ResourceGroup
from ct_azure.utils.utils import AzureUtils
from ct_azure.utils.utils import ctlogger

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
import logging
import collections
import traceback
import threading
import time
import datetime
import Queue
import gc
import _strptime

logger = logging.getLogger('cloud_monitor.Subscription')

class Subscription:

    # constanns
    ACTION_DISCOVER_SUB = 1 # discover a subscription
    ACTION_CLEANUP      = 2 # cleanup a subscription


    GROUP_DELETE_CMD = "Microsoft.Resources/subscriptions/resourcegroups/delete"
    GROUP_ADD_CMD = "Microsoft.Resources/subscriptions/resourceGroups/write"

    def __init__(self, subscription_id, customerAccount):
        self.customerAccount = customerAccount
        self.logger = ctlogger(logger, {'custname' : self.customerAccount.customerName \
                                                + "-" + self.customerAccount.tenantName})
        self.subscription_id = subscription_id
        self.res_group_list = []
        self.discovery_done = False 
        self.discovery_mode_slow = False 
        self.status = AzureUtils.STATUS_LOGIN
        self.subscription_info = collections.namedtuple("Info", ["Id", "name",
                                                                 "computeClient",
                                                                 "networkClient",
                                                                 "storageClient"])
        self.monitor_thread = threading.Thread(target=self.subscription_monitor)
        self.discovery_thread = threading.Thread(target=self.discovery)
        self.event_thread = threading.Thread(target=self.event_handler)
        self.discovery_q = Queue.PriorityQueue()
        self.monitor_q = Queue.PriorityQueue()
        self.flow_q = Queue.PriorityQueue()
        self.event_handler_q = Queue.PriorityQueue()
        self.role_assignments_q = Queue.PriorityQueue()
        self.discovery_thread.start()
        self.event_thread.start()
        if self.customerAccount.service_principal_id != None:
            self.logger.info("service principal given")
        self.error = ""
        self.warning = ""
        self.last_event_time =  datetime.datetime.utcnow()
        self.logger.info("Subscription initialisation id : {}".format(subscription_id))

    def event_handler(self):
        while True:
            item = self.event_handler_q.get()

            if (item == self.ACTION_CLEANUP):
                self.status = AzureUtils.STATUS_DELETE
                self.discovery_q.put(item)
                self.monitor_q.put(item)
                self.flow_q.put(item)
                self.role_assignments_q.put(item)
                if self.monitor_thread.is_alive():
                    self.monitor_thread.join(60)
                if self.discovery_thread.is_alive():
                    self.discovery_thread.join(300)
                self.do_cleanup()
                break

        self.status = AzureUtils.STATUS_DELETE_COMPLETE
        self.logger.info("Exiting the event handlder thread of subscription {}".format(self.subscription_id))

    def enqueue_action(self, action):
        if (action == self.ACTION_DISCOVER_SUB):
            self.discovery_q.put(action)
        elif (action == self.ACTION_CLEANUP):
            self.event_handler_q.put(action)
        else:
            self.logger.error("Unknown enqueue action {}".format(action))
         
    def monitor_role_assignments(self):
        self.logger.info("Inside monitor role assignments thread")
        while True:

            try:
                item = self.role_assignments_q.get(timeout=300)
                if (item == self.ACTION_CLEANUP):
                    self.logger.info("Role assignments cleanup initiated")
                    break
            except Queue.Empty:
                pass

            self.logger.info("Validating role assignments")

            if AzureUtils.validate_role_assignments(self.customerAccount, self.subscription_id):
                if self.status == AzureUtils.STATUS_LOGIN_FAILED:
                    self.status = AzureUtils.STATUS_FLOW_STARTED
                    self.error = ""
                # In case the discovery has not started first time because of incorrect role assignments
                if self.discovery_done == False:
                    self.enqueue_action(Subscription.ACTION_DISCOVER_SUB)
            else:
                self.status = AzureUtils.STATUS_LOGIN_FAILED
                self.error = "Invalid Role assignments of sub id " + str(self.subscription_id)

        self.logger.info("Exiting verify role assignments thread")


    def do_validation(self):
        self.logger.info("Doing account validation")
        """
        if self.customerAccount.service_principal_id != None and \
                not AzureUtils.validate_role_assignments(self.customerAccount, self.subscription_id):
            self.error = "Invalid Role assignments of sub id " + str(self.subscription_id)
            return False
        """
        subscription_name, sub_status = AzureUtils.valid_subscription(self.subscription_id, self.customerAccount.credentials)

        self.subscription_info.name = subscription_name

        if not sub_status:
            self.logger.info("Invalid subscription id")
            self.error = "Invalid Subscription Id " + str(self.subscription_id)
            return False

        return True


    def poll_flows(self, sa):
        sa.poll_latest_flows()
        return sa.name

    def flow_monitor(self):
        self.status = AzureUtils.STATUS_FLOW_STARTED
        executor = ThreadPoolExecutor(max_workers = 4)
        while True:
            self.logger.info("Start flow for all accounts")
            try:
                item = self.flow_q.get(timeout=60)
                if (item == self.ACTION_CLEANUP):
                    self.logger.info("Subscription {} cleanup initiated".format(self.subscription_id))
                    break
            except Queue.Empty:
                pass

            sa_list_full = []
            for group in self.res_group_list:
                sa_list = group.get_storage_accounts()
                for sa in sa_list:
                    self.logger.info("Added SA {} of group {} for flow polling".format(sa.name, group.name))
                    sa_list_full.append(sa)

            if len(sa_list_full):
                results = executor.map(self.poll_flows, sa_list_full, timeout=300)
                try:
                    for result in results:
                        self.logger.info("Read flow from account {}".format(result))
                except Exception as ex:
                    self.logger.info("Exception in flow")
                    self.logger.exception(ex)

            self.logger.info("Finished flow for all accounts")
            gc.collect()

        self.logger.info("Exiting the flow thread of subscription {}".format(self.subscription_id))
        gc.collect()

    def discovery(self):
        while True:
            item = self.discovery_q.get()

            if (item == self.ACTION_CLEANUP):
                break
            elif (item == self.ACTION_DISCOVER_SUB):
                if self.do_validation():
                    self.do_discovery()
                else:
                    self.status = AzureUtils.STATUS_LOGIN_FAILED
            else:
                self.logger.error("Unknown discovery action {}".format(item))

        self.logger.info("Exiting the discovery thread of subscription {}".format(self.subscription_id))

    def do_group_discovery(self, resource_group):
        resource_group.do_discovery()

    def do_cleanup(self):
        self.logger.info("Cleanup of subscription {}".format(self.subscription_id))
        
        for group in self.res_group_list:
            self.logger.info("Cleanup resource group : {}".format(group.name))
            group.do_cleanup()
        AzureUtils.add_delete_tag_sub(self.subscription_id)
        AzureUtils.delete_from_db_sub(self.subscription_id)

        self.res_group_list = []
        try:
            self.subscription_info.computeClient.close()
            self.subscription_info.networkClient.close()
            self.subscription_info.monitorClient.close()
            self.subscription_info.storageClient.close()
        except Exception as ex:
            self.logger.error("Failed to close handles of sub {}".format(self.subscription_id))
            self.logger.exception(ex)
        gc.collect()

    def do_discovery(self):
        self.status = AzureUtils.STATUS_LOGIN_COMPLETED
        start = time.time()
        self.logger.info("Initialize the API clients for Azure Subscription {}".format(self.subscription_id))
        subscription_info = {}
        self.subscription_info.Id = self.subscription_id
        try:
            self.subscription_info.computeClient = ComputeManagementClient(self.customerAccount.credentials, 
                                                                            self.subscription_id)
            self.subscription_info.networkClient = NetworkManagementClient(self.customerAccount.credentials, 
                                                                            self.subscription_id, api_version='2020-04-01')
            self.subscription_info.storageClient = StorageManagementClient(self.customerAccount.credentials, 
                                                                            self.subscription_id, api_version='2019-06-01')
            self.subscription_info.monitorClient = MonitorManagementClient(self.customerAccount.credentials,
                                                                            self.subscription_id)
            self.subscription_info.resourceClient = ResourceManagementClient(self.customerAccount.credentials, 
                                                                            self.subscription_id)
        except Exception as ex:
            self.error = "Error initializing the azure handles"
            self.logger.exception(ex)

        client = self.subscription_info.resourceClient
        for item in client.resource_groups.list():
            self.logger.info("Discovered resource group : {}".format(item.name))
            resource_group = ResourceGroup(item.name, self.subscription_info, self.customerAccount)
            self.res_group_list.append(resource_group)

        if self.discovery_mode_slow == True:
            for group in self.res_group_list:
                group.do_discovery()
        
        if self.discovery_mode_slow == False:
            with ThreadPoolExecutor(max_workers = 8) as executor:
                results = executor.map(self.do_group_discovery, self.res_group_list, 
                                    timeout=300, chunksize=1)

        self.logger.info("Completed in {} seconds!!!".format(time.time() - start))
        self.subscription_info.resourceClient.close()
        self.subscription_info.resourceClient = None
        self.discovery_done = True
        self.monitor_thread.start()

    @staticmethod
    def resource_monitor(group):
        try:
            return group.resource_monitor()
        except Exception as ex:
            self.logger.exception(ex)
            return None

    def get_total_resource_count(self):
        vm_cache_count = 0
        sa_cache_count = 0
        for group in self.res_group_list:
            vm_cache_count += group.get_total_virtual_machines()
            sa_cache_count += group.get_total_storage_accounts()

        return (vm_cache_count + sa_cache_count)

    # Fast Integrity check - Check only if the resource count matches at subscription level
    # Slow Integrity Check - Check if the resource name also matches
    def resource_group_integrity_check(self, fast):
        start = time.time()
        total = self.get_total_resource_count()

        compute = self.subscription_info.computeClient
        storage = self.subscription_info.storageClient
        azure_vm_count = AzureUtils.get_virtual_machine_list_all(compute)
        azure_sa_count = AzureUtils.get_storage_account_list_all(storage)
        total_azure = len(list(azure_vm_count)) + len(list(azure_sa_count))

        if total == total_azure:
            if fast:
                self.logger.info("Fast Integrity check completed in {} seconds account {}!!!"\
                        .format((time.time() - start), self.customerAccount.customerName))
                return
        else:
            self.logger.info("Azure subscription count {}".format(total_azure))
            self.logger.info("Total cache count {}".format(total))

        rediscover_list = []
        for group in self.res_group_list:
            azure_vm_list = AzureUtils.get_virtual_machine_list(group)
            azure_vm_len = len(list(azure_vm_list))
            vm_cache_count = group.get_total_virtual_machines()

            azure_sa_list = AzureUtils.get_storage_account_list(group)
            azure_sa_len = len(list(azure_sa_list))
            sa_cache_count = group.get_total_storage_accounts()

            if vm_cache_count != azure_vm_len or \
                   sa_cache_count != azure_sa_len:
                self.logger.info("Azure VM count {} not matching cache count {} or" \
                        .format(azure_vm_len, vm_cache_count))
                self.logger.info("Azure SA count {} not matching cache count {}" \
                        .format(azure_sa_len, sa_cache_count))
                self.logger.info("Rediscover group {}".format(group.name))
                rediscover_list.append(group)

        if len(rediscover_list):
            for group in rediscover_list:
                group.do_cleanup()
                group.do_discovery()

        self.logger.info("Slow Integrity check completed in {} seconds account {}!!!"\
                .format((time.time() - start), self.customerAccount.customerName))

    def resgroup_handle_event(self, log):
        action = log.operation_name.value
        res_group_name = log.resource_group_name
        if action == self.GROUP_ADD_CMD:
            self.logger.info("Discovered a new group {}".format(res_group_name))
            group = next((group for group in self.res_group_list if group.name == res_group_name), None)
            if group == None:
                resource_group = ResourceGroup(res_group_name, self.subscription_info, self.customerAccount)
                self.res_group_list.append(resource_group)
                resource_group.do_discovery()
        elif action == self.GROUP_DELETE_CMD:
            self.logger.info("Delete a new group {}".format(res_group_name))
            group = next((group for group in self.res_group_list if group.name == res_group_name), None)
            if group != None:
                group.do_cleanup()
                self.res_group_list.remove(group)


    def resource_group_monitor(self):
        select = ",".join([
            "eventTimestamp",
            "eventName",
            "operationName",
            "resourceGroupName",
            "resourceId",
            "status",
            "category"])
 
        filter = " and ".join([ "eventTimestamp ge '{}'".format(self.last_event_time),
                    "resourceProvider eq 'Microsoft.Resources'"])

        monitorClient = self.subscription_info.monitorClient
        try:
            activity_logs = monitorClient.activity_logs.list(filter=filter, select=select)
        except Exception as ex:
            self.logger.exception(ex)
            self.logger.info("Failed to get activity log for sub {}".format(self.name))
            return 

        for log in activity_logs:
            if log.status.value == "Succeeded" and \
                log.category.value == "Administrative" and \
                log.event_name.value == "EndRequest":
                    self.resgroup_handle_event(log)

            last_event_time = str(log.event_timestamp).split('+')[0]
            self.last_event_time = AzureUtils.increment_microsecond(last_event_time)

    def subscription_monitor(self):
        self.logger.info("Start the resource monitor of {}".format(self.subscription_id))
        self.status = AzureUtils.STATUS_FLOW_STARTED

        count = 0
        executor = ThreadPoolExecutor(max_workers = 4)
        while (True):

            self.logger.info("Check for activity in susbscription {} for account {}" \
                                .format(self.subscription_id, self.customerAccount.customerName))

            try:
                item = self.monitor_q.get(timeout=60)
                if (item == self.ACTION_CLEANUP):
                    self.logger.info("Subscription {} cleanup initiated".format(self.subscription_id))
                    break
            except Queue.Empty:
                pass

            try:
                #monitoring specifically the RG events
                self.resource_group_monitor()
            except Exception as ex:
                self.logger.exception(ex)

            
            results = executor.map(self.resource_monitor, self.res_group_list, timeout=180)
            try:
                for result in results:
                    if result == None:
                        continue

                    event_list = result[1]
                    if len(event_list):
                        group = next((group for group in self.res_group_list if group.name == result[0]), None)
                        if group != None:
                            self.logger.info("handle update for {} ".format(group.name))
                            group.handle_update(event_list)

            except Exception as ex:
                self.logger.error("Error in resource monitoring")
                self.logger.error(ex)
                self.logger.error(traceback.format_exc())

            # Every 5 minutes do a fast integrity check
            # Every 10 minutes do a slow integrity check
            count = count + 1
            if count % 5  == 0:
                fast = True
                gc.collect()

                if count % 10 == 0:
                    fast = False 

                try:
                    self.resource_group_integrity_check(fast)
                except Exception as ex:
                    self.logger.exception(ex)

        self.logger.info("Exiting the resource monitor of {}".format(self.subscription_id))
        gc.collect()
