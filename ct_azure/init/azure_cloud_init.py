import logging
import threading
from threading import Lock
import sys
import os
from ct_azure.utils.utils import getTenantId
from ct_azure.access.account import *
from ct_azure.utils.utils import *
import db.database as database
import utils.cloud_monitor_config as config
from ct_azure.utils.utils import AzureUtils
import time
import gc

logger = logging.getLogger('cloud_monitor.azure_cloud_init')

loginList = list()
customerAccountList = list()
gLoginObj = None
customerAdditionLock = Lock()

def azure_service_init():
    account_list = AzureUtils.getAzureCustomerAccountFromDB()
    num_accounts = len(account_list)
    if num_accounts:
        logger.info("Number of Azure accounts detected from db : {}".format(num_accounts))
        for account in account_list:
            logger.info("Adding Azure account {}".format(account["acc_name"]))
            tenant_id_cm = getTenantId(account["tenant_cm"])
            addCustomerAccounts_internal(account["tenant_cm"], 
                                         account["acc_name"],
                                         account["tenant_id"],
                                         account["service_principal_id"],
                                         account["client_id"],
                                         account["client_key"],
                                         account["subscription_list"],
                                         False)
    else:
        logger.info("No Azure account exists")

    logger.info("Azure Service Initialization complete")


def getAzureCustomerAccountList():
    return customerAccountList

def getAzureCustomerAccount(customerName, tenantName):
    account = next((account for account in customerAccountList if (account.customerName == customerName \
                            and account.tenantIdCm == getTenantId(tenantName))), None)
    return account


def checkSubscriptionExists(subscriptionList):
    # For each input, check if already exists
    for subscription_input in subscriptionList:
        for account in customerAccountList:
            for subscription in account.tenant.subscriptions:
                if subscription.subscription_id == subscription_input:
                    return True
    return False

def addAzureCustomerAccounts(tenantName, customerName, tenantId, servicePrincipalId, clientId, clientKey, \
                                                    subscriptionList, cloudType):
    return addCustomerAccounts_internal(tenantName, customerName, tenantId, servicePrincipalId, \
                                        clientId, clientKey, subscriptionList, True)

def addCustomerAccounts_internal(tenantName, customerName, tenantId, servicePrincipalId, clientId, \
                                                clientKey, subscriptionList, db_add) :
    tenantIdCm = getTenantId(tenantName)
    if tenantIdCm == None:
        logger.error("Error tenant name {}".format(tenantName))
        return "Invalid Tenant Name", False
    
    if customerName == None or tenantId == None or clientId == None or clientKey == None or subscriptionList == None \
            or not customerName or not tenantId or not clientId or not clientKey or len(subscriptionList) == 0:
        logger.error("Invalid inputs are provided customerName : {}, tenantId : {}, clientId : {}, clientKey : {}, subscriptionList : {}".format(
            customerName, tenantId, clientId, clientKey, subscriptionList))
        return "Invalid input provided", False

    logger.info("Inside Azure addCustomerAccounts_internal")
    if checkSubscriptionExists(subscriptionList):
        logger.error("Subscription alreaady exists {}".format(subscriptionList))
        return "Subscription already exists", False
 
    json_obj = { "cloud_type" : "Azure",
                 "tenant_name"   : tenantName,
                 "customer_name" : customerName,
                 "tenant_id"   : tenantId,
                 "service_principal_id" : servicePrincipalId,
                 "client_id"   : clientId,
                 "client_key"   : clientKey,
                 "account_status" : 'Account Check In-Progress',
                 "account_error" : '',
                 "subscription_list" : subscriptionList }

    if db_add:
        database.insertIntoDb( json_obj, 'customers')

    azureCustAcc = AzureCustomerAccount(customerName, tenantId, servicePrincipalId, clientId, clientKey, subscriptionList, \
                                                tenantIdCm, tenantName)
    customerAccountList.append(azureCustAcc)
    azureCustAcc.do_discovery()
    return "Customer addition Successful", True

def markCustomerForDeletionAzure(customerName, tenantName):
    tenantIdCm = getTenantId(tenantName)
    customerAccount = next((account for account in customerAccountList if account.customerName == customerName \
                                    and account.tenantIdCm == tenantIdCm),  None)
    if customerAccount:
        logger.info("Found the Azure customer account for cleanup customerName: {}, tenantName: {}".format(customerAccount.customerName, tenantName))
        customerAccount.tenant.do_cleanup()
    else:
        logger.error("Could not find the Azure account internally for deletion")

    return True

#Cleanup customer account
def cleanupCustomerAccountThread(customerName, tenantName):
    account = getAzureCustomerAccount(customerName, tenantName)
    i = 0
    while account:
        time.sleep(1)
        i = i + 1
        logger.info("Waiting for Azure customer deletion account {} status {}" \
                                .format(customerName, account.tenant.get_status()))
        if (account.tenant.get_status() == "Account Deleted"):
            logger.info("Successfully deleted Azure customer account {}".format(account.customerName))
            break
        if i > 60:
            break;

    if account != None:
        account.tenant = None
        customerAccountList.remove(account)
    gc.collect()
    try:
        database.removeFromDb('customers', {"customer_name" : customerName, "cloud_type" : "Azure", \
                            "tenant_name" : tenantName })
    except:
        logger.error("Failed to delete Azure customer account customerName: {}, tenantName: {}".format(customerName, tenantName))

def cleanupCustomerAccountAzure(customerName, tenantName):
    # Create a daemon thread to monitor cleanup by all modules and delete it
    logger.info("cleanupCustomerAccountAzure called customerName: {}, tenantName: {}".format(customerName, tenantName))
    t1 = threading.Thread(target=cleanupCustomerAccountThread, args=(customerName, tenantName))
    t1.start()


def deleteCustomerAccountAzure(customerName, tenantName):
    markCustomerForDeletionAzure(customerName, tenantName)
    cleanupCustomerAccountAzure(customerName, tenantName)

