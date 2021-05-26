from ct_azure.resources.virtual_network import VirtualNetwork
from ct_azure.resources.network_security_group import NetworkSecurityGroup
from ct_azure.utils.net_utils import AzureNetUtils
from ct_azure.utils.utils import AzureUtils, ctlogger
import logging
from ipaddress import IPv4Network
logger = logging.getLogger("cloud_monitor.NetworkInterface")

# NetworkInterface
# https://docs.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.v2020_03_01.models.networkinterface?view=azure-python

class NetworkInterface:

    def __init__(self, interface, subscription_info, customerAccount):
        self.interface = interface
        self.subscription_info = subscription_info
        self.customerAccount = customerAccount
        self.logger = ctlogger(logger, {'custname' : self.customerAccount.customerName \
                                                + "-" + self.customerAccount.tenantName})
        self.networkClient = self.subscription_info.networkClient
        self.public_ip = []
        self.private_ip = []
        self.subnets = []
        self.nsg = None
        self.connected_vm = interface.virtual_machine
        self.mac_address = interface.mac_address
        self.location = interface.location
        self.id = interface.id
        if interface.name != None:
            self.name = interface.name
        else:
            self.name = "private"

    def load_network_interface(self):
        self.logger.info("Registering interface {}".format(self.name))
        # Private IP Configuration
        self.get_private_ip_config()
        self.log_ip(self.private_ip)

        # Public IP Configuration
        self.get_public_ip_config()
        self.log_ip(self.public_ip)

        # ACLs
        self.logger.info("Load the NSG")
        self.get_nsg()

    def get_nsg(self):
        azure_nsg = self.interface.network_security_group
        if azure_nsg:
            group = AzureUtils.get_group_from_id(self.customerAccount, azure_nsg.id)
            if group == None:
                self.logger.error("NSG {} found but no group".format(azure_nsg.id))
                return
                                                       
            nsg_parts = azure_nsg.id.split("/")
            nsg_name = nsg_parts[8]
            nsg = group.get_security_group(nsg_name)
            if nsg == None:
                azure_nsg = self.networkClient.network_security_groups.get(group.name, nsg_name)
                nsg = NetworkSecurityGroup(azure_nsg, self.subscription_info, self.customerAccount)
                group.add_security_group(nsg)
            self.nsg = nsg


    def get_public_ip_config(self):
        nw_info = self.interface.ip_configurations
        for ip in nw_info:
            if ip.public_ip_address == None:
                continue
            ip_reference = ip.public_ip_address.id
            ip_reference = ip_reference.split('/')
            ip_group = ip_reference[4]
            ip_name = ip_reference[8]

            ip_config = {}
            public_ip = self.networkClient.public_ip_addresses.get(ip_group, ip_name)
            ip_config["ip_address"] = public_ip.ip_address
            ip_config["subnet"] = public_ip.public_ip_prefix
            ip_config["vnet"] = None
            ip_config["prefix"] = ip.subnet.address_prefix
            ip_config["netmask"] = "255.255.255.255"
            self.public_ip.append(ip_config)

    def get_private_ip_config(self):
        nw_info = self.interface.ip_configurations
        for ip in nw_info:
            if ip.private_ip_address == None:
                continue
            ip_config = {}
            ip_config["ip_address"] = ip.private_ip_address
            ip_config["version"] = ip.private_ip_address_version
            subnet_info = ip.subnet.id.split('/')
            ip_config["group"] = subnet_info[4]
            ip_config["vnet"] = subnet_info[8]
            ip_config["prefix"] = ip.subnet.address_prefix


            group = ip_config["group"]
            vnet = ip_config["vnet"]
            subnet = subnet_info[10]

            group_obj = AzureUtils.get_group_from_id(self.customerAccount, ip.subnet.id)
            assert(group != None)
            assert(group == group_obj.name)

            vnet_obj = group_obj.get_virtual_network(vnet)
            if vnet_obj == None:
                azure_vnet = self.networkClient.virtual_networks.get(group_obj.name, vnet)
                vnet_obj = VirtualNetwork(azure_vnet, self.subscription_info, self.customerAccount)
                vnet_obj.load_virtual_network()
                group_obj.add_virtual_network(vnet_obj)

            for subnet_obj in vnet_obj.subnetList:
                self.subnets.append(subnet_obj)

            for subnet_obj in vnet_obj.subnetList:
                if subnet_obj.name == subnet:
                    ip_config["subnet"] = subnet_obj.subnet.address_prefix
                    netmask = IPv4Network(subnet_obj.subnet.address_prefix).netmask
                    if netmask:
                        ip_config["netmask"] = str(netmask)

            self.private_ip.append(ip_config)

    def get_private_ip(self):
        return self.private_ip[0]["ip_address"]

    def get_public_ip(self):
        if len(self.public_ip):
            return self.public_ip[0]["ip_address"]

    def get_mac_address(self):
        return self.mac_address

    def log_ip(self, ip_list):
        if len(ip_list):
            for ip in ip_list:
                self.logger.info("IP Address: {}".format(ip["ip_address"]))
                if ip["vnet"]:
                    self.logger.info("Subnet: {}".format(ip["subnet"]))

    def get_vnet(self):
        return self.private_ip[0]["vnet"]




