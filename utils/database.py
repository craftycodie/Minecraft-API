from datetime import datetime, timezone
import time

def getclassicservers(mongo):
    def removeExpired(server):
        if not "expiresAt" in server:
            return False

        if (server["expiresAt"].replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)):
            mongo.db.classicservers.delete_many({"_id": server["_id"]})
            # Hang on to the salt
            if (server["salt"] != None):
                mongo.db.classicservers.insert_one({"ip": server["ip"], "port": server["port"], "salt": server["salt"]})
            return False
            
        return True
    classicservers = list(mongo.db.classicservers.find())
    classicservers = list(filter(removeExpired, classicservers))
    classicservers.sort(key=lambda x: len(x["players"]) if "players" in x else 0, reverse=True)
    return classicservers