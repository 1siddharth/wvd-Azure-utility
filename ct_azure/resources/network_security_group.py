import logging
from azure.mgmt.network.models import SecurityRuleDirection
from ct_azure.utils.utils import ctlogger

logger = logging.getLogger("cloud_monitor.NetworkSecurityGroup")

# Network Security Group
# https://docs.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.v2020_03_01.models.networksecuritygroup?view=azure-python

class NetworkSecurityGroup:

    def __init__(self, nsg, subscription_info, customerAccount):
        self.azure_nsg = nsg
        self.subscription_info = subscription_info
        self.customerAccount = customerAccount
        self.logger = ctlogger(logger, {'custname' : self.customerAccount.customerName \
                                                + "-" + self.customerAccount.tenantName})
        self.name = nsg.name
        self.id = nsg.id

    def load_network_security_group(self):
        self.logger.info("Loading NSG {}".format(self.name))
        self.id = self.azure_nsg.id
        self.flow_logs = self.azure_nsg.flow_logs

    def is_flow_logs_enabled(self):
        return self.flow_logs.enabled

    def get_storage_id(self):
        return self.flow_logs.storage_id

    def get_security_rules(self):
        return self.azure_nsg.security_rules

    def populate_rules(self, rules, azure_rule, direction):
        if direction == azure_rule.direction:
            rule = {}
            rule["name"] = azure_rule.name
            rule["priority"] = str(azure_rule.priority)

            if azure_rule.source_address_prefix == "*":
                rule["source"] = "any"
            elif len(azure_rule.source_address_prefixes) > 0:
                rule["source"] = ", ".join(azure_rule.source_address_prefixes)
            else:
                rule["source"] = azure_rule.source_address_prefix

            if azure_rule.source_port_range == "*":
                rule["source_ports"] = "any"
            elif len(azure_rule.source_port_ranges) > 0:
                rule["source_ports"] = ", ".join(azure_rule.source_port_ranges)
            else:
                rule["source_ports"] = azure_rule.source_port_range

            if azure_rule.destination_address_prefix == "*":
                rule["destination"] = "any"
            elif len(azure_rule.destination_address_prefixes) > 0:
                rule["destination"] = ", ".join(azure_rule.destination_address_prefixes)
            else:
                rule["destination"] = azure_rule.destination_address_prefix

            if azure_rule.destination_port_range == "*":
                rule["destination_ports"] = "any"
            elif len(azure_rule.destination_port_ranges) > 0:
                rule["destination_ports"] = ", ".join(azure_rule.destination_port_ranges)
            else:
                rule["destination_ports"] = azure_rule.destination_port_range

            if azure_rule.protocol == "*":
                rule["protocol"] = "any"
            else:
                rule["protocol"] = azure_rule.protocol

            rule["access"] = azure_rule.access
            rules.append(rule)

    def get_rules(self, direction):
        rules = []
        for azure_rule in self.azure_nsg.default_security_rules:
            self.populate_rules(rules, azure_rule, direction)

        for azure_rule in self.azure_nsg.security_rules:
            self.populate_rules(rules, azure_rule, direction)

        return rules




