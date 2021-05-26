import logging
import sys
import os
aws_enabled   = True
azure_enabled = True
gcp_enabled   = False

logger = logging.getLogger('cloud_monitor.service_helper')

if __name__ == "__main__":
    verifyAccess("data", "Demo") 
