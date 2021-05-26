from flask import Flask, request, jsonify,Response,make_response
from flask_cors import CORS
from pymongo import MongoClient
import os
import logging
import signal
import threading
import traceback
import sys
sys.path.insert(0, "./..")
import db.database as database
from utils.cloud_monitor_config import cfg
from threading import Lock
import pdb
# Azure
from ct_azure.init.azure_cloud_init import azure_service_init
from ct_azure.init.azure_cloud_init import deleteCustomerAccountAzure
from ct_azure.init.azure_cloud_init import addAzureCustomerAccounts 

customerRegistrationLock = Lock()

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.disabled = True
CORS(app)
URL = '/cloudmonitor/api/v1/'


logger = logging.getLogger('cloud_monitor.service')
#
# REST API to add customer details
#

@app.route(URL + '<string:tenant_name>' + '/customer-registration', methods=['POST'])
def addCustomerDetails(tenant_name):
    global singleLogin
    global customerAdditionInProcess
    logger.info("Before aquiring lock for addCustomerDetails")
    customerRegistrationLock.acquire()
    logger.info("After aquiring lock for addCustomerDetails")
    try :
        logger.info("Inside addCustomerDetails")
        pdb.set_trace()
        data = request.get_json(force=True)
        logger.info("Incoming data[{}]".format(data))

        cloudType = data.get("cloud_type")
        if cloudType == "azure":
            customerName = data.get("customer_name")
            tenantId = data.get("tenant_id")
            servicePrincipalId = data.get("service_principal_id")
            clientId = data.get("client_id")
            clientKey = data.get("client_key")
            subscriptionList = data.get("subscription_list")

            str, response = addAzureCustomerAccounts(tenant_name, customerName, tenantId, servicePrincipalId, clientId, clientKey, subscriptionList, \
                                                        cloudType)

            status = {}
            status['message'] = str

            if response == True:
                status['type'] = 'success'
                customerRegistrationLock.release()
                return jsonify(status)
            else:
                status['type'] = 'failed'
                customerRegistrationLock.release()
                return make_response(jsonify(status), 400)
    except Exception:
        status = {}
        status['message'] = "unable to add customer"
        return jsonify(status)    
                   
def service_init():
    logger.info("Inside service_init()")
    data = {'cloud_type' : 'AWS'}
    try:
        api_thread = threading.Thread(target=rest_api_thread)
        api_thread.start()
        return api_thread
    except:
        logger.error("Error:  Unable to Create Rest API server Thread")
        return None
    # Init the azure service
    azure_service_init()

def rest_api_thread():
    try:
        logger.info("Inside rest_api_thread")
        app.run(host=cfg['cloud_api_ip'] ,port=cfg['cloud_api_port'],
                threaded=True, use_reloader=False, debug=False)
    except Exception:
        logger.error("Failed to start API server")
    return



if __name__ == '__main__':
    database.db_init()
    app.run(host='0.0.0.0', port=5050)

