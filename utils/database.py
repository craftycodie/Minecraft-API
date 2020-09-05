from datetime import datetime, timezone
import time

def getclassicservers(mongo):
    def removeExpired(server):
        if (server["expiresAt"].replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)):
            mongo.db.classicservers.delete_one({"_id": server["_id"]})
            return False
            
        return True
    classicservers = list(mongo.db.classicservers.find())
    return list(filter(removeExpired, classicservers))