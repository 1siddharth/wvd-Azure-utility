import logging
import socket
import struct

logger = logging.getLogger('cloud_monitor.AzureNetUtils')

class AzureNetUtils:

    def __init__(self):
        pass

    @staticmethod
    def ip_to_int(addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]



