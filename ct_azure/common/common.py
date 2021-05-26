import logging
import db.database as database

logger = logging.getLogger("cloud_monitor.utils_common")

def getTenantName(tenantId):
    db = database.colormaster_db_client["colormaster"]
    response = db["tenants"].find_one({"_id": tenantId})
    if response:
        return response["name"]
    logger.error("ERROR No Tenant Name exists for tenant id:"+ str(tenantId))
    return None
