import collections
import time
import pdb
import logging
import hashlib

from ct_azure.resources.network_interface import NetworkInterface
from ct_azure.resources.virtual_network import VirtualNetwork 
from ct_azure.resources.disk import Disk 
from ct_azure.utils.utils import AzureUtils, ctlogger
from ct_azure.utils.net_utils import AzureNetUtils

logger = logging.getLogger('cloud_monitor.VirtualMachine')


# Virtual Machine
# https://docs.microsoft.com/en-us/python/api/azure-mgmt-compute/azure.mgmt.compute.v2019_12_01.models.virtualmachine?view=azure-python
#
class VirtualMachine:
    
    def __init__(self, azure_vm, subscription_info, customerAccount):
        self.logger = ctlogger(logger, {'custname' : customerAccount.customerName \
                                                + "-" + customerAccount.tenantName})
        self.vm = azure_vm
        self.subscription_info = subscription_info
        self.customerAccount = customerAccount
        self.tenantName = customerAccount.tenantName
        self.name = azure_vm.name
        self.os_disk = None
        self.groups_name = self.vm.id.split('/')[4]
        self.azure_id = azure_vm.id
        self.resource_id = hashlib.md5(str(self.azure_id).encode()).hexdigest()
        self.dependency_resolved = False
        self.interfaces = []
        self.cm_tag_list = self.get_cm_tags()

    def update_azure_vm(self, azure_vm):
        self.vm = azure_vm

    def get_resource_id(self):
        return self.resource_id

    def get_azure_id(self):
        return self.azure_id
    
    def get_cm_tags(self):
        vm = AzureUtils.get_from_db_id(self.get_azure_id(), self.tenantName)
        if vm == None or 'tags' not in vm or vm['tags'] == None:
            return []
        else:
            return vm["tags"]

    def register_virtual_machine(self):
        try:
            self.logger.info("Register vm : {}".format(self.name))
            ct_vm = {}
            self.interfaces = []

            self.logger.info("Discover interfaces")
            self.discover_interfaces()
            self.logger.info("Discovered interfaces")
            self.populate_vm_data(ct_vm)

            self.logger.info("Check for vm {}".format(ct_vm["azure_id"]))
            if (AzureUtils.get_from_db_id(ct_vm["azure_id"], self.tenantName) != None):
                self.logger.info("Delete from DB {}".format(self.name))
                AzureUtils.add_delete_tag_res(self.get_azure_id(), self.tenantName)
                AzureUtils.delete_from_db_id(self.get_azure_id(), self.tenantName)

            self.logger.info("Add to db {}".format(self.name))
            AzureUtils.insert_to_db_vm(ct_vm, self.tenantName)
        except Exception as e:
            self.logger.error("Register VM failed, VM: {}".format(self.name))
            self.logger.exception(e)

    def get_security_rules(self):
        self.logger.info("Get security rules for VM {}".format(self.name))

        nsgs = []
        for interface in self.interfaces:
            self.logger.info("Checks NSGs for interface {}".format(interface.name))
            if interface.nsg:
                nsg = next((nsg for nsg in nsgs if nsg["name"] == interface.nsg.name), None)
                if nsg:
                    nsg["interfaces"].append(interface.name)
                    continue

                nsg = {}
                nsg["interfaces"] = []
                nsg["subnets"] = []
                nsg["name"] = interface.nsg.name
                nsg["interfaces"].append(interface.name)
                nsg["inbound_rules"] = interface.nsg.get_rules("Inbound")
                nsg["outbound_rules"] = interface.nsg.get_rules("Outbound")
                self.logger.info("Add interface nsg {} rule for vm {}".format(interface.nsg.name, self.name))
                nsgs.append(nsg)

        for interface in self.interfaces:
            for subnet in interface.subnets:
                self.logger.info("Check NSG for subnet {}".format(interface.name + "/" + subnet.name))
                if subnet.nsg:
                    self.logger.info("Subnet has NSG {}".format(subnet.nsg.name))
                    nsg = next((nsg for nsg in nsgs if nsg["name"] == subnet.nsg.name), None)
                    if nsg:
                        if subnet.name not in nsg["subnets"]:
                            nsg["subnets"].append(subnet.name)
                        continue

                    nsg = {}
                    nsg["interfaces"] = []
                    nsg["subnets"] = []
                    nsg["name"] = subnet.nsg.name
                    nsg["subnets"].append(subnet.name)
                    nsg["inbound_rules"] = subnet.nsg.get_rules("Inbound")
                    nsg["outbound_rules"] = subnet.nsg.get_rules("Outbound")
                    self.logger.info("Add subnet nsg {} rule for vm {}".format(subnet.nsg.name, self.name))
                    nsgs.append(nsg)
        return nsgs

    def unregister_virtual_machine(self):
        self.logger.info("unregister virtual machine {}".format(self.name))
        vm = AzureUtils.get_from_db_id(self.get_azure_id(), self.tenantName)
        if vm != None:
            self.cm_tag_list = vm["tags"]
            AzureUtils.add_delete_tag_res(self.get_azure_id(), self.tenantName)
            AzureUtils.delete_from_db_id(self.get_azure_id(), self.tenantName)

        # delete the interfaces
        self.logger.info("Delete interfaces")
        for interface in self.interfaces:
            group_obj = AzureUtils.get_group_from_id(self.customerAccount, interface.id)
            if group_obj:
                group_obj.delete_network_interface(interface)

    def populate_vm_data(self, ct_vm):
        ct_vm["name"] = self.name
        ct_vm["sub_id"] = self.subscription_info.Id
        ct_vm["sub_name"] = self.subscription_info.name
        ct_vm["tenantIdCm"] = self.customerAccount.tenantIdCm
        ct_vm["customerName"] = self.customerAccount.customerName
        ct_vm["os_type"] = self.get_os_type()
        ct_vm["os_class"] = self.get_os_class()
        ct_vm["location"] = self.get_location().capitalize()
        ct_vm["azure_id"] = self.get_azure_id()
        ct_vm["publicIp"] = self.interfaces[0].get_public_ip()
        ct_vm["privateIp"] = self.interfaces[0].get_private_ip()
        ct_vm["account_id"] = self.customerAccount.tenant_id
        ct_vm["createdDate"] = self.get_creation_date()
        ct_vm["subnet"] = self.interfaces[0].private_ip[0]["subnet"]
        ct_vm["vnet"] = self.interfaces[0].private_ip[0]["vnet"]
        ct_vm["res_group"] = self.get_resource_group()
        ct_vm["status"] = self.get_vm_status()
        ct_vm["size"] = self.get_size()
        ct_vm["interfaces"] = self.get_interface_list()
        ct_vm["network"] = self.get_network_list()
        ct_vm["mac_address"] = self.interfaces[0].get_mac_address()
        ct_vm["tags"] = self.get_azure_tags(False)
        ct_vm["cm_tags"] = self.get_azure_tags(True)
        ct_vm["resource_id"] = self.get_resource_id()
        ct_vm["security_rules"] = self.get_security_rules()
        ct_vm["zone"] = self.get_zone()

    def get_zone(self):
        if self.vm.zones != None:
            if len(self.vm.zones):
                return self.vm.zones[0]
        return "N/A"

    def get_azure_tags(self, cm_tags):
        tag_list = []
        policy_tags = ['application','environment','location','roles','service']

        if self.vm.tags:
            for tag in self.vm.tags:
                t = {
                    "actualKey"   : tag,
                    "lowerKey"    : tag.lower(),
                    "actualValue" : self.vm.tags[tag],
                    "lowerValue"  : self.vm.tags[tag].lower(),
                    "actualValueV1" : [],
                    "lowerValueV1"  : []
                    }
                if t['lowerKey'] in policy_tags:
                    t["actualKey"] = tag.title()
                    t["actualValueV1"].append(self.vm.tags[tag])
                    t["lowerValueV1"].append(self.vm.tags[tag].lower())
                    if len(self.cm_tag_list):
                        tag = next((tagi for tagi in self.cm_tag_list if (tagi["lowerKey"] ==  t["lowerKey"]\
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

    def get_resource_group(self):
        return self.vm.id.split('/')[4]

    def get_os_type(self):
        try:
            return  " ".join([self.vm.storage_profile.os_disk.os_type, \
                    self.vm.storage_profile.image_reference.sku])
        except Exception as ex:
            self.logger.error(ex)
            return self.vm.storage_profile.os_disk.os_type

    def get_os_class(self):
        return self.vm.storage_profile.image_reference.offer

    def get_os_disk_res_group(self):
        return self.vm.storage_profile.os_disk.managed_disk.id.split("/")[4]

    def get_os_disk_name(self):
        return self.vm.storage_profile.os_disk.name
    
    def get_size(self):
        return self.vm.hardware_profile.vm_size

    def get_location(self):
        return self.vm.location

    def get_vmId(self):
        return self.vm.vm_id

    def get_public_ip(self):
        return self.vm.publicIps

    def get_network_list(self):
         network_list = []
         for intf in self.interfaces:
            #TBD handling Ipv6 cases
            if len(intf.public_ip):
                for ipconfig in intf.public_ip:
                    if ipconfig["ip_address"] == None:
                        continue
                    s = {
                        "ip": ipconfig["ip_address"],
                        "netmask" : ipconfig["netmask"],
                        "ipInt" : AzureNetUtils.ip_to_int(ipconfig["ip_address"]),
                        "prefix" : ipconfig["prefix"]
                        }
                    network_list.append(s)
    
            if len(intf.private_ip):
                for ipconfig in intf.private_ip:
                    if ipconfig["ip_address"] == None:
                        continue
                    s = {
                        "ip": ipconfig["ip_address"],
                        "netmask" : ipconfig["netmask"],
                        "ipInt" : AzureNetUtils.ip_to_int(ipconfig["ip_address"]),
                        "prefix" : ipconfig["prefix"]
                    }
                    network_list.append(s)

         return network_list

    def get_interface_list(self):
        interface_list = []
        for intf in self.interfaces:
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
                    interface_list.append(s)

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
                    interface_list.append(s)

        return interface_list

    def get_vm_status(self):
        computeClient = self.subscription_info.computeClient
        instance_view = computeClient.virtual_machines.get(self.groups_name, 
                                self.vm.name, expand='instanceView').instance_view
        if len(instance_view.statuses) >= 2:
            status = instance_view.statuses[1].display_status
            status_split = status.split()
            if len(status_split) > 1:
                return status_split[1]
            else:
                return status
        return "Unknown"

    # VM loads interfaces
    # Interface loads vnets and nsgs
    # vnets loads the nsgs
    def discover_interfaces(self):
        networkClient = self.subscription_info.networkClient

        for reference in self.vm.network_profile.network_interfaces:
            group_obj = AzureUtils.get_group_from_id(self.customerAccount, reference.id)
            assert(group_obj != None)

            ni = reference.id.split('/')
            group = ni[4]
            name  = ni[8]
       
            interface = group_obj.get_network_interface(name)
            if interface == None:
                azure_interface = self.subscription_info.networkClient.network_interfaces.get(group, name)
                interface = NetworkInterface(azure_interface, self.subscription_info, self.customerAccount)
                interface.load_network_interface()
                group_obj.add_network_interface(interface)

            self.interfaces.append(interface)

    def get_creation_date(self):
        try:
            disk_res_group = self.get_os_disk_res_group()
            disk_name = self.get_os_disk_name()

            if self.os_disk == None:
                azure_disk = self.subscription_info.computeClient.disks.get(disk_res_group, disk_name)
                disk_obj = Disk(azure_disk, self.subscription_info, self.customerAccount)
                self.os_disk = disk_obj

            return self.os_disk.get_creation_time()

        except Exception as e:
            self.logger.error(e)
            return None
