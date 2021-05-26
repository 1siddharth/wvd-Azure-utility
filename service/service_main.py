import os
import sys
import signal
import traceback
import time
from service import service_init
sys.path.append(os.path.join(sys.path[0],"../"))

import db.database as db
import utils.cloud_monitor_config as config
from utils.cloud_monitor_log import log_init

def initialize():
    logger = None
    try:
        logger = log_init('cloud_monitor', config.cfg['apilog'], config.cfg['log_maxbytes'], config.cfg['log_filecount'])
        db.db_init()
        api_thread = service_init()
        if api_thread:
            # Control flow remains within this block throughout the lifespan
            # of the spawned thread, allowing us to listen for interrupts
            while api_thread.is_alive():
                # Sleep for 60 seconds
                time.sleep(60)
                pass
        else:
            logger.error("API thread is dead!!!!")
            raise Exception('Server thread spawning failed')
    except KeyboardInterrupt:
        os.kill(os.getpid(), signal.SIGTERM)
    except:
         print("Cloud monitoring initialization failed")
         #logger.error("Cloud monitoring initialization failed")
         print(traceback.format_exc())
         os.kill(os.getpid(), signal.SIGTERM)

if __name__ == '__main__':
    DEBUG_MODE_ = False 
    if DEBUG_MODE_ == True:
        while 1:
            time.sleep(1000)
    initialize()
