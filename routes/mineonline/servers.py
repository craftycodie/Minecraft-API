from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4, UUID
from utils.servers import *
from datetime import datetime
from pymongo import IndexModel, ASCENDING, DESCENDING, errors
import sys
from utils.versions import get_versions

def register_routes(app, mongo):
    @app.route('/mineonline/listserver.jsp', methods=["POST"])
    def addserver():
        port = request.json['port']
        maxUsers = request.json['max']
        name = request.json['name']
        onlinemode = request.json['onlinemode']
        md5 = request.json['md5']
        whitelisted = request.json['whitelisted']
        whitelistUsers = request.json['whitelistUsers']
        whitelistIPs = request.json['whitelistIPs']
        whitelistUUIDs = request.json['whitelistUUIDs']
        bannedUsers = request.json['bannedUsers']
        bannedIPs = request.json['bannedIPs']
        bannedUUIDs = request.json['bannedUUIDs']

        players = []
        if("players" in request.json):
            players = request.json["players"]

        versionName = "Unknown Version"

        if 'ip' in request.json and request.json['ip'] != '':
            ip = request.json['ip'] # new to mineonline to allow classic servers on different IPs
        else:
            ip = request.remote_addr

        owner = None
        ownerUUID = None

        if "owner" in request.json and request.json["owner"] != "":
            owner = request.json["owner"]
            try:
                users = mongo.db.users
                ownerUUID = users.find_one({"user": request.json["owner"]})["uuid"]
            except:
                pass

        classicservers = mongo.db.classicservers

        user = None

        if(port == None):
            port = "25565"

        versions = get_versions()

        for version in versions:
            if(version["md5"] == md5 and version["type"] == "server"):
                if('clientVersions' in version):
                    versionName = str(version["clientVersions"]).replace("'", "").replace("[", "").replace("]", "")
                else:
                    versionName = version["name"]
            pass

        try:
            # Find an existing salted server
            currentlisting = classicservers.find_one({"port": port, "ip": ip, "salt": {'$nin': [None, '']}})
            # Delete the rest
            if(currentlisting):
                _id = currentlisting['_id']
                classicservers.delete_many({"port": port, "ip": ip, "_id": {"$ne": _id}})

                users = request.json['users'] if 'users' in request.json else currentlisting['users']

                classicservers.update_one({"_id": _id}, { "$set": {
                    "createdAt": datetime.utcnow(),
                    "ip": ip,
                    "port": port,
                    "users": users,
                    "maxUsers": maxUsers,
                    "name": name,
                    "onlinemode": onlinemode,
                    "versionName": versionName,
                    "md5": md5,
                    "whitelisted": whitelisted,
                    "whitelistUsers": whitelistUsers,
                    "whitelistedIPs": whitelistIPs,
                    "whitelistUUIDs": whitelistUUIDs,
                    "bannedUsers": bannedUsers,
                    "bannedIPs": bannedIPs,
                    "bannedUUIDs": bannedUUIDs,
                    "players": players,
                    "ownerUUID": ownerUUID,
                    "owner": owner
                }})

            else:
                # Delete existing server record
                classicservers.delete_many({"port": port, "ip": ip})
                _id = ObjectId()

                users = request.json['users'] if 'users' in request.json else 0


                while(True):
                    cursor = classicservers.find_one(sort = [("realmId", DESCENDING)])
                    seq = cursor["realmId"] + 1 if cursor != None and "realmId" in cursor and cursor["realmId"] != None else 1
                    
                    try:
                        classicservers.insert_one({
                            "_id": _id,
                            "realmId": seq,
                            "createdAt": datetime.utcnow(),
                            "ip": ip,
                            "port": port,
                            "users": users,
                            "maxUsers": maxUsers,
                            "name": name,
                            "onlinemode": onlinemode,
                            "versionName": versionName,
                            "md5": md5,
                            "whitelisted": whitelisted,
                            "whitelistUsers": whitelistUsers,
                            "whitelistIPs": whitelistIPs,
                            "whitelistUUIDs": whitelistUUIDs,
                            "bannedUsers": bannedUsers,
                            "bannedIPs": bannedIPs,
                            "bannedUUIDs": bannedUUIDs,
                            "players": players,
                            "ownerUUID": ownerUUID,
                            "owner": owner
                        })
                    except errors.WriteError as writeError:
                        if writeError.code == 11000:
                            continue
                        else:
                            return Response("Something went wrong.", 500)

                    break
            
            
            return Response("ok")

        except:
            print("Unexpected error:", sys.exc_info()[1])
            return Response("Something went wrong.", 500)

        return Response("Something went wrong.", 500)

    @app.route('/mineonline/listservers.jsp')
    def listservers():
        uuid = request.args.get('user')
        sessionId = request.args.get('sessionId')

        try:
            users = mongo.db.users
            user = users.find_one({"uuid" : uuid, "sessionId": ObjectId(sessionId)})
        except:
            return Response("Invalid Session", 401)

        if (user == None):
            return Response("Invalid Session", 401)

        mineOnlineServers = list(mongo.db.classicservers.find())
        featuredServers = list(mongo.db.featuredservers.find())
        featuredServers = [dict(server, **{'isMineOnline': False}) for server in featuredServers]
        servers = mineOnlineServers + featuredServers

        def mapServer(x): 
            if(not"md5" in x):
                return
            if(not "whitelisted" in x):
                return

            if ("public" in x and x["public"] == False):
                return

            status = NONE

            if (x["onlinemode"] == False):
                status = OFFLINEMODE
            
            if (x["whitelisted"] == True and "whitelistUsers" in x and "whitelistIPs" in x and "whitelistUUIDs" in x):
                if(user["user"] in x["whitelistUsers"] or request.remote_addr in x["whitelistIPs"]):
                    status = ON_THE_WHITELIST
                else:
                    status = NOT_ON_THE_WHITELIST

            if ("bannedUsers" in x and "bannedIPs" in x and "bannedUUIDs" in x and (user["user"] in x["bannedUsers"] or request.remote_addr in x["bannedIPs"] or uuid in x["bannedUUIDs"])):
                status = BANNED

            return { 
                "createdAt": str(x["createdAt"]) if "createdAt" in x else None,
                "ip": x["ip"] if status != BANNED and status != NOT_ON_THE_WHITELIST else None,
                "port": x["port"] if status != BANNED and status != NOT_ON_THE_WHITELIST else None,
                "users": x["users"] if "users" in x else "0",
                "maxUsers": x["maxUsers"] if "maxUsers" in x else "24",
                "name": x["name"],
                "onlinemode": x["onlinemode"],
                "md5": x["md5"],
                "isMineOnline": x["isMineOnline"] if "isMineOnline" in x else True,
                "status": status,
                "players": x["players"] if "players" in x else []
            }

        servers = list(map(mapServer, servers))
        servers = list(filter(filterServer, servers))

        return Response(json.dumps(servers))