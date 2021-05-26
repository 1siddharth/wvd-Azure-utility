from azure.storage.blob import BlockBlobService 

import datetime
import collections
import logging
import threading
from ct_azure.resources.private_endpoint import PrivateEndpoint
from ct_azure.resources.virtual_machine import VirtualMachine
from ct_azure.resources.storage_account import StorageAccount
from ct_azure.resources.virtual_network import VirtualNetwork
from ct_azure.resources.network_interface import NetworkInterface
from ct_azure.resources.network_security_group import NetworkSecurityGroup
from ct_azure.utils.utils import AzureUtils, ctlogger


logger = logging.getLogger('cloud_monitor.ResourceGroup')

# Resource Types
TYPE_VM = "virtualMachines"
TYPE_SA = "storageAccounts"
TYPE_NSG = "networkSecurityGroups"
TYPE_PE = "privateEndpoints"
TYPE_INTF = "networkInterfaces"
TYPE_VNET = "virtualNetworks"

# Resource Actions
ACTION_DELETE = "delete"
ACTION_NONE   = "none"

class ResourceGroup:
    def __init__(self, name, subscription_info, customerAccount):
        self.name = name
        self.customerAccount = customerAccount
        self.subscription_info = subscription_info
        self.logger = ctlogger(logger, {'custname' : self.customerAccount.customerName \
                                                + "-" + self.customerAccount.tenantName})
        self.discovery_done = False
        self.virtualMachines = []
        self.storageAccounts = []
        self.virtualNetworks = []
        self.securityGroups = []
        self.interfaces = []
        self.privateEndpoints = []
        self.vm_lock = threading.Lock()
        self.sa_lock = threading.Lock()
        self.vnet_lock = threading.Lock()
        self.intf_lock = threading.Lock()
        self.nsg_lock = threading.Lock()
        self.pe_lock = threading.Lock()

        self.last_event_time = str(datetime.datetime.utcnow())
        self.storageAccountsKey = {}

    def add_virtual_machine(self, new_vm):
        self.vm_lock.acquire()
        item = next((vm for vm in self.virtualMachines if vm.name == new_vm.name), None)
        if item == None:
            self.virtualMachines.append(new_vm)
        self.vm_lock.release()

    def add_private_endpoint(self, new_pe):
        self.pe_lock.acquire()
        item = next((pe for pe in self.privateEndpoints if pe.name == new_pe.name), None)
        if item == None:
            self.logger.debug("adding private endpoint {}".format(new_pe.name))
            self.privateEndpoints.append(new_pe)
        self.pe_lock.release()

    def get_private_endpoint(self, name):
        return next((pe for pe in self.privateEndpoints if pe.name == name), None)
    
    def get_virtual_machine(self, name):
        return next((vm for vm in self.virtualMachines if vm.name == name), None)

    def get_total_virtual_machines(self):
        return len(self.virtualMachines)

    def get_total_storage_accounts(self):
        return len(self.storageAccounts)

    def add_network_interface(self, new_intf):
        self.intf_lock.acquire()
        item = next((intf for intf in self.interfaces if intf.name == new_intf.name), None)
        if item == None:
            self.logger.info("Add interface {}".format(new_intf.name))
            self.interfaces.append(new_intf)
        self.intf_lock.release()

    def delete_network_interface(self, del_intf):
        self.intf_lock.acquire()
        self.logger.info("Delete interface {}".format(del_intf.name))
        try:
            self.interfaces.remove(del_intf)
        except Exception as ex:
            self.logger.info("Interface {} not found".format(del_intf.name))
        self.intf_lock.release()

    def get_network_interface(self, name):
        return next((intf for intf in self.interfaces if intf.name == name), None)

    def add_virtual_network(self, new_vnet):
        self.vnet_lock.acquire()
        item = next((vnet for vnet in self.virtualNetworks if vnet.name == new_vnet.name), None)
        if item == None:
            self.logger.info("adding vnet {} to group {}".format(new_vnet.name, self.name))
            self.virtualNetworks.append(new_vnet)
        self.vnet_lock.release()

    def delete_virtual_network(self, vnet):
        self.vnet_lock.acquire()
        self.logger.info("Delete vnet {}".format(vnet.name))
        try:
            self.virtualNetworks.remove(vnet)
        except Exception as ex:
            self.logger.info("Vnet {} not found".format(vnet.name))
        self.vnet_lock.release()

    def get_virtual_network(self, name):
        return next((vnet for vnet in self.virtualNetworks if vnet.name == name), None)

    def add_security_group(self, new_nsg):
        self.nsg_lock.acquire()
        item = next((nsg for nsg in self.securityGroups if nsg.name == new_nsg.name), None)
        if item == None:
            self.securityGroups.append(new_nsg)
        self.nsg_lock.release()

    def get_security_group(self, name):
        return next((nsg for nsg in self.securityGroups if nsg.name == name), None)

    def delete_pe(self,del_pe):
        self.pe_lock.acquire()
        self.logger.info("Delete pe {}".format(del_pe.name))
        try:
            self.privateEndpoints.remove(del_pe)
        except Exception as ex:
            self.logger.info("PE {} not found".format(del_pe.name))
        self.pe_lock.release()
    def get_intf(self, name):
        return next((intf for intf in self.interfaces if intf.name == name), None)

    def delete_security_group(self, del_nsg):
        self.nsg_lock.acquire()
        self.logger.info("Delete nsg {}".format(del_nsg.name))
        try:
            self.securityGroups.remove(del_nsg)
        except Exception as ex:
            self.logger.info("NSG {} not found".format(del_nsg.name))
        self.nsg_lock.release()

    def delete_intf(self, del_intf):
        self.intf_lock.acquire()
        self.logger.info("Delete intf {}".format(del_intf.name))
        try:
            self.interfaces.remove(del_intf)
        except Exception as ex:
            self.logger.info("INTF {} not found".format(del_intf.name))
        self.intf_lock.release()

    def add_storage_account(self, new_sa):
        self.sa_lock.acquire()
        item = next((sa for sa in self.storageAccounts if sa.name == new_sa.name), None)
        if item == None:
            self.storageAccounts.append(new_sa)
        self.sa_lock.release()

    def get_storage_account(self, name):
        return next((sa for sa in self.storageAccounts if sa.name == name), None)

    def get_storage_accounts(self):
        return self.storageAccounts
          
    def do_discovery(self):
        self.logger.info("Start discovery of group {}".format(self.name))
        # Discover Storage Accounts
        azure_sa_list = AzureUtils.get_storage_account_list(self)
        if azure_sa_list:
            for storage_account in azure_sa_list:
                storage_key = AzureUtils.get_storage_account_key(self,storage_account.name)
                storageAccount = StorageAccount(storage_account, self.subscription_info, self.customerAccount, storage_key)
                storageAccount.register_storage_account()
                self.add_storage_account(storageAccount)

        # Discover Network Security Groups
        azure_nsg_list = AzureUtils.get_nsg_list(self)
        if azure_nsg_list:
            for azure_nsg in azure_nsg_list:
                nsg = NetworkSecurityGroup(azure_nsg, self.subscription_info, self.customerAccount)
                nsg.load_network_security_group()
                self.add_security_group(nsg)

        # Discover Virtual netowrks
        azure_vnet_list = AzureUtils.get_vnet_list(self)
        if azure_vnet_list:
            for azure_vnet in azure_vnet_list:
                virtualNetwork = VirtualNetwork(azure_vnet, self.subscription_info, self.customerAccount)
                virtualNetwork.load_virtual_network()
                self.add_virtual_network(virtualNetwork)

        # Discover network interfaces
        azure_interface_list = AzureUtils.get_interface_list(self)
        if azure_interface_list:
            for azure_intf in azure_interface_list:
                interface = NetworkInterface(azure_intf, self.subscription_info, self.customerAccount)
                interface.load_network_interface()
                self.logger.info("Adding interface {} to group {}".format(interface.name, self.name))
                self.add_network_interface(interface)

        # Discover virtual machines
        azure_vm_list = AzureUtils.get_virtual_machine_list(self)
        if azure_vm_list:
            for azure_vm in azure_vm_list:
                virtualMachine = VirtualMachine(azure_vm, self.subscription_info, self.customerAccount)
                virtualMachine.register_virtual_machine()
                self.add_virtual_machine(virtualMachine)
        
        #Discover private endpoints
        #azure.mgmt.network.v2020_04_01.models._models.PrivateEndpoint
        self.logger.info("discovering pe of group {}".format(self.name))
        azure_pe_list = AzureUtils.get_private_endpoint_list(self)
        if azure_pe_list:
            for azure_pe in azure_pe_list:
                privateEndpoint = PrivateEndpoint(azure_pe, self.subscription_info, self.customerAccount)
                privateEndpoint.load_private_endpoint()
                #add only if not existing
                self.add_private_endpoint(privateEndpoint)
                self.logger.info("Added pe {} to group {}".format(privateEndpoint.name, self.name))
        
        # Discover Disks
        self.discovery_done = True 

        self.logger.info("****************************")
        self.logger.info("Complete discovery of group {}".format(self.name))
        for vm in self.virtualMachines:
            self.logger.info("Discovered VirtualMachine for group {} is {}".format(self.name, vm.name))
        for sa in self.storageAccounts:
            self.logger.info("Discovered StorageAccount for group {} is {}".format(self.name, sa.name))
        for vn in self.virtualNetworks:
            self.logger.info("Discovered Vnet for group {} is {}".format(self.name, vn.name))
        for sg in self.securityGroups:
            self.logger.info("Discovered NSG for group {} is {}".format(self.name, sg.name))
        for intf in self.interfaces:
            self.logger.info("Discovered Interface for group {} is {}".format(self.name, intf.name))

    def do_cleanup(self):
        for vm in self.virtualMachines:
            vm.unregister_virtual_machine()
            self.virtualMachines.remove(vm)
        for sa in self.storageAccounts:
            sa.unregister_storage_account()
            self.storageAccounts.remove(sa)

    def create_events_from_id(self, vm_list):
        self.logger.info(vm_list)
        event_list = []

        for vm in vm_list:
            id_split = vm.split("/")
            event = collections.namedtuple("update_event", [ "name", "id", "type", "action"])
            event.id = vm
            event.name = id_split[8]
            event.type = id_split[7]
            event.group = id_split[4]
            self.logger.info("Appending event from {} ".format(vm))
            event_list.append(event)
        return event_list
        
    # https://docs.microsoft.com/en-us/python/api/azure-mgmt-monitor/azure.mgmt.monitor.v2015_04_01.models.eventdata?view=azure-python
    def resource_monitor(self):
        update_event = collections.namedtuple("update_event",
                                    [ "name",
                                      "id",
                                      "type",
                                      "action"
                                    ])
        event_list = []
        
        select = ",".join([
                    "eventTimestamp",
                    "eventName",
                    "operationName",
                    "resourceGroupName",
                    "resourceId",
                    "status",
                    "category"
                ])
        filter = " and ".join([ "eventTimestamp ge '{}'".format(self.last_event_time),
                               "resourceGroupName eq '{}'".format(self.name)])
        monitorClient = self.subscription_info.monitorClient
        try:
            self.logger.debug("event log filter is {} for {}".format(filter, self.name))
            activity_logs = monitorClient.activity_logs.list(filter=filter, select=select)
        except Exception as ex:
            self.logger.error(ex)
            return (self.name, event_list)

        for log in activity_logs:
            resource_type = None
            updated_events = []
            resource_id_split = log.resource_id.split('/')
            if len(resource_id_split) >= 9:
                resource_type = resource_id_split[7]
                resource_name = resource_id_split[8]

            if resource_type != TYPE_VM and resource_type != TYPE_SA and \
                    resource_type != TYPE_NSG and resource_type != TYPE_INTF and \
                    resource_type != TYPE_VNET and resource_type != TYPE_PE:
                continue
            if resource_type == TYPE_PE and \
                len(resource_id_split) > 9:
                continue    
            if log.status.value == "Succeeded" and \
                log.category.value == "Administrative" and \
                log.event_name.value == "EndRequest":
                    update_event = AzureUtils.get_event_info(log)
                    if update_event.action != "none":
                        if update_event.type == TYPE_NSG:
                            updated_events = self.process_nsg_event(update_event)
                            if len(updated_events):
                                event_list.extend(updated_events)
                        if update_event.type == TYPE_PE:
                            self.logger.info("Received a PE event")
                            updated_events = self.process_pe_event(update_event)
                            if len(updated_events):
                                event_list.extend(updated_events)
                                self.logger.info("extended event after process_pe_event")
                        if update_event.type == TYPE_INTF:
                            updated_events = self.process_intf_event(update_event)
                            if len(updated_events):
                                event_list.extend(updated_events)
                        if update_event.type == TYPE_VNET:
                            updated_events = self.process_vnet_event(update_event)
                            if len(updated_events):
                                event_list.extend(updated_events)
                        else:
                            self.logger.info("Added event {} of type {} action {} in event_list".\
                                    format(update_event.id, update_event.type, update_event.action))

                            event_list.append(update_event)
            last_event_time = str(log.event_timestamp).split('+')[0]
            # Note the last event time, so that next iteration can read from there
            if self.compare_timestamps(last_event_time.split('.')[0], self.last_event_time.split('.')[0]):
                self.last_event_time = AzureUtils.increment_microsecond(last_event_time)

        return (self.name, event_list)

    def compare_timestamps(self, new_time, old_time):
        new_time_object = datetime.datetime.strptime(new_time, '%Y-%m-%d %H:%M:%S')
        old_time_object = datetime.datetime.strptime(old_time, '%Y-%m-%d %H:%M:%S')
        return (new_time_object > old_time_object)

    #get sa list and crete events for the SA
    def process_pe_event(self, update_event):
        updated_events = []
        group = AzureUtils.get_resource_group(self.subscription_info.Id, update_event.group)
        if group != None:
            #if pe is added first time this will be None
            pe = group.get_private_endpoint(update_event.name)
            self.logger.info("Processing the pe {} from {}".format(update_event.name,group.name)) 
            if pe != None:
                self.logger.info("deleting the pe {} from {}".format(update_event.name,group.name))
                pe.unregister_private_endpoint()
                self.logger.info("unregistered the pe {} from {}".format(update_event.name,group.name)) 
                group.delete_pe(pe)
                self.logger.info("deleted the pe {} from {}".format(update_event.name,group.name))
        sa_list = AzureUtils.get_sa_list_from_pe(self, update_event.name)
        if len(sa_list) == 0:
            self.logger.info("SA list from cache of PE {} ".format(update_event.name))
            sa_list = AzureUtils.get_sa_list_from_pe_cache(self.subscription_info.Id,\
                    update_event.name)
        if len(sa_list):
            self.logger.info("SA list from pe {} ".format(update_event.name))
            updated_events = self.create_events_from_id(sa_list)
        return updated_events
    
    # When NSG event happens, we need to refresh all the resources assoicated with the NSG
    def process_nsg_event(self, update_event):
        self.logger.info("Process NSG event {}".format(update_event.name))
        updated_events = []
        group = AzureUtils.get_resource_group(self.subscription_info.Id, update_event.group)
        if group != None:
            nsg = group.get_security_group(update_event.name)
            if nsg != None:
                group.delete_security_group(nsg)

        vm_list = AzureUtils.get_vm_list_from_nsg(self.subscription_info.Id, update_event.name)
        if len(vm_list):
            self.logger.info(vm_list)
            updated_events = self.create_events_from_id(vm_list)
        self.logger.info("Number of updated events {} group {}".format(len(vm_list), self.name))

        # Though NSG deleted, delete the references to it
        # NSG has two references, one in interface and one in subnet
        AzureUtils.delete_nsg_reference(self.subscription_info.Id, update_event.name)

        return updated_events

    # process interface event
    def process_intf_event(self, update_event):
        self.logger.info("Process interface event {}".format(update_event.name))
        updated_events = []
        group = AzureUtils.get_resource_group(self.subscription_info.Id, update_event.group)
        if group != None:
            intf = group.get_intf(update_event.name)
            if intf != None:
                group.delete_intf(intf)

        # Return the list of VMs associated with this interface
        vm_list = AzureUtils.get_vm_from_intf(self.subscription_info.Id, update_event.name)
        if len(vm_list):
            self.logger.info(vm_list)
            updated_events = self.create_events_from_id(vm_list)
        self.logger.info("Number of updated events {} group {}".format(len(vm_list), self.name))
        return updated_events

    # process vnet event
    def process_vnet_event(self, update_event):
        self.logger.info("Process vnet event {}".format(update_event.name))
        updated_events = []
        group = AzureUtils.get_resource_group(self.subscription_info.Id, update_event.group)
        if group != None:
            vnet = group.get_virtual_network(update_event.name)
            if vnet != None:
                group.delete_virtual_network(vnet)

        # Return the list of VMs associated with this vnet
        vm_list = AzureUtils.get_vm_list_from_vnet(self.subscription_info.Id, update_event.name)
        if len(vm_list):
            self.logger.info(vm_list)
            updated_events = self.create_events_from_id(vm_list)
        self.logger.info("Number of updated events {} group {}".format(len(vm_list), self.name))
        return updated_events

    def load_resource(self, event, azure_resource):
        if event.type == TYPE_VM:
            vm = VirtualMachine(azure_resource, self.subscription_info, self.customerAccount)
            vm.register_virtual_machine()
            self.virtualMachines.append(vm)
        elif event.type == TYPE_SA:
            storage_key = AzureUtils.get_storage_account_key(self, azure_resource.name)
            sa = StorageAccount(azure_resource, self.subscription_info, self.customerAccount, storage_key)
            sa.register_storage_account()
            self.storageAccounts.append(sa)

    def unload_resource(self, event, resource):
        if event.type == TYPE_VM:
            resource.unregister_virtual_machine()
            self.virtualMachines.remove(resource)
        elif event.type == TYPE_SA:
            resource.unregister_storage_account()
            self.storageAccounts.remove(resource)

    def get_resource_from_event_type(self, event):
        self.logger.info("Finding resource {} from cache".format(event.id))
        resource = None
        if (event.type == TYPE_VM):
            resource = next((vm for vm in self.virtualMachines if vm.azure_id.lower() == event.id.lower()), None)
        elif (event.type == TYPE_SA):
            resource = next((sa for sa in self.storageAccounts if sa.azure_id.lower() == event.id.lower()), None)
            if resource == None:
                resource = next((sa for sa in self.storageAccounts if sa.name.lower() == event.name.lower()), None)
        return resource

    def get_azure_resource(self, event):
        if event.type == TYPE_VM:
            return AzureUtils.get_virtual_machine(self, event.name)
        elif event.type == TYPE_SA:
            return AzureUtils.get_storage_account(self, event.name)

    def process_event_list(self, event_list):
        event_list_updated = []

        # Remove duplicate resource id
        for event in event_list:
            self.logger.info("Check for duplicate {}".format(event.name))
            if event not in event_list_updated:
                self.logger.info("Add event {}".format(event.name))
                event_list_updated.append(event)

        return event_list_updated

    def refresh_resource(self, event, resource, azure_resource):
        if event.type == TYPE_VM:
            resource.unregister_virtual_machine()
            resource.update_azure_vm(azure_resource)
            resource.register_virtual_machine()
        elif (event.type == TYPE_SA):
            resource.unregister_storage_account()
            resource.update_azure_sa(azure_resource)
            resource.register_storage_account()

    # When we handle event, there are 4 possibilities
    # Resource is neither in CM nor in Azure. Ignore.
    # Resource is in CM not in Azure. Delete it
    # Resource is not in CM in Azure. Create it
    # Resource exists in both. Refresh it
    def handle_resource_refresh(self, event):
        self.logger.info("Received event for resource {} of type {} of group {} "\
                                    .format(event.name, event.type, self.name))
        resource = self.get_resource_from_event_type(event)
        if resource != None:
            self.logger.info("Found resource {} in cache from event".format(event.id))
        azure_resource = self.get_azure_resource(event)
        if azure_resource != None:
            self.logger.info("Found resource {} in azure from event".format(event.id))

        # refresh resource
        if resource and azure_resource:
            self.logger.info("Refresh resource {} in group {}".format(event.name, self.name))
            self.refresh_resource(event, resource, azure_resource)

        # create resource
        elif resource == None and azure_resource:
            self.logger.info("Create resource {} in group {}".format(event.name, self.name))
            self.load_resource(event, azure_resource)

        # Delete resource
        elif azure_resource == None and resource:
            self.logger.info("Delete resource {} in group {}".format(event.name, self.name))
            self.unload_resource(event, resource)

        # No Action
        elif azure_resource == None and resource == None:
            self.logger.info("Resource does not exist")

    def handle_update(self, event_list):
        self.logger.info("Number of events to process {} group {}".format(len(event_list), self.name))
        event_list = self.process_event_list(event_list)

        for event in event_list:
            self.logger.info("Process event for {}".format(event.name))
            if event.group == self.name:
                self.handle_resource_refresh(event)
            else:
                # It is possible that the event is generated for a resource from this group
                # however it needs refresh of resources in other groups 
                group = AzureUtils.get_resource_group(self.subscription_info.Id, event.group)
                if group != None:
                    group.handle_resource_refresh(event)

