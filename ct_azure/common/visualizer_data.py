import logging
import db.database as database
from ct_azure.utils.utils import AzureUtils
from utils.utils import getTenantId
logger = logging.getLogger('cloud_monitor.visualizer_data')

def retrieveResourceIdsForAzure( vpc_id ):
    logger.info('retrieveResourceIdsForVpc')
    resid =[]
    #res_list = database.retrieveFromDb( 'resources',{{'_import_vpc' : vpc_id },{'resource_id':1,'_id':0}})
    res_list = database.retrieveFromDb( 'resources',{'resource_id' : vpc_id })
    for res in res_list:
        r = { 'name'       :res['hostname'],
              'resourceid' :res['resource_id']
            }
        resid.append(r)
    return resid

def createStorageAccountPayload(tenant_id) :
    logger.info('createStorageAccountPayloads')
    customer_list = AzureUtils.get_customer_accounts(tenantId=tenant_id)
    if len(customer_list) == 0:
        logger.info("No customer present")
        return []
    resid = []
    for customer in customer_list:
        sas = customer.tenant.get_sas()
        if len(sas) < 1 :
            continue
        for sa in sas:
            r = { 'name'      : sa.name,
                  'resourceid' : sa.resource_id
                }
            resid.append(r)
    return resid 

def createAzurePayload( tenant_name ):
    logger.info('creating AzureInstancePayload')
    res_list_full = []
    vpc_dict = {}
    tenant_id = getTenantId(tenant_name)
    customer_list = AzureUtils.get_customer_accounts(tenantId=tenant_id)
    if len(customer_list) == 0:
        logger.info("No customer present")
        return []
    for customer in customer_list:
        logger.info("adding vnet info for customer {}".format(customer.customerName))
        vnets = customer.tenant.get_vnets()
        if len(vnets) < 1 :
            logger.info("No vnets for account {}".format(customer.customerName))
            continue

        for vnet in vnets :
            res_list = customer.tenant.get_resource_id_from_vnet( vnet.id )
            logger.info(res_list)
            vpc_data = {
                        'VnetId'                  : vnet.name,
                        'State'                   : vnet.provisioning_state,
                        'Subnet'                  : "default",
                        'IsDefault'               : "true",
                        'Tags'                    : "vnet",
                        'Resources'               : res_list
                        }
            if vnet.location not in vpc_dict:
                vpc_dict[vnet.location] = []
            vpc_dict[vnet.location].append(vpc_data)

        for r,v in vpc_dict.items():
            d = {'region' : r,
                 'vnets'  : v }
            res_list_full.append( d )
    logger.debug("adding sa info for customer {}".format(customer.customerName))

    sa = createStorageAccountPayload(tenant_id)
    sa_data = [{
                 'VnetId'                  : 'AzureStorageAccounts',
                 'State'                   : '',
                 'Subnet'                  : '',
                 'IsDefault'               : '',
                 'Tags'                    : '',
                 'Resources'               : sa
              }]
    
    ds = {'region' : 'AzureStorage',
          'vnets' : sa_data }

    res_list_full.append(ds)
    logger.debug("Final List of resources")
    logger.debug(res_list_full)
    return res_list_full
