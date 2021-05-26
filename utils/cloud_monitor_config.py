import json
import os
import logging

logger = logging.getLogger('cloud_monitor.config')

conf_path = "../utils/cloud_config.conf"
cfg = None
gProduction = 1
with open(conf_path) as cfg_file:
     cfg = json.load(cfg_file)

     # If production build, load the details form secrets 
     if (not 'UNIT_TEST' in os.environ) and gProduction:
         
         cfg['mongo_uri'] =  "mongodb://xoft2:colors321@127.0.0.1:27017/?authSource=xoft"
         cfg['cloud_db_uri'] =  "mongodb://xoft2:colors321@127.0.0.1:27017/?authSource=xoft"

     print("Loaded config file: {}".format(conf_path))
     print json.dumps(cfg, indent=2)
     print "\n"

def getURL(type):
     if type in cfg:
        return cfg[type]
     else:
        return None
