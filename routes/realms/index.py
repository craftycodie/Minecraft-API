from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from utils.servers import *
from bson.objectid import ObjectId
from uuid import UUID

from routes.realms.management import register_routes as register_management_routes

def register_routes(app, mongo):
    register_management_routes(app, mongo)

    @app.route('/mco/client/outdated')
    def realmsoutdated():
        return Response("", 200)

    @app.route('/payments/unused')
    def paymentsunused():
        return Response("0", 200)

    @app.route('/mco/client/compatible')
    def realms():
        return Response("COMPATIBLE")

    @app.route('/invites/count/pending')
    def realmsInviteCount():
        return Response("0")

    @app.route('/trial')
    def realmsTrial():
        return Response("false")

    @app.route('/mco/available')
    def realmsAvailable():
        return Response("true")

    @app.route('/invites/<realmId>', methods=["DELETE"])
    def leaveRealm(realmId):
        return Response("Not yet implemented.", 400)

    @app.route('/mco/v1/news')
    def realmsNews():
        return make_response(json.dumps({
            "newsLink": "https://discord.com/invite/RBKKnxf"
        }))

    @app.route('/activities/liveplayerlist')
    def liveplayerlist():
        mineOnlineServers = list(mongo.db.classicservers.find())
        lists = []
        for server in mineOnlineServers:
            if "realmId" in server:
                playerlist = {
                    "serverId": server["realmId"],
                }

                if(len(server["players"]) > 0):
                    playerlist["playerList"] = server["players"]
                
                lists.append(playerlist)
        print(json.dumps({ "lists": lists }))
        return make_response(json.dumps({ "lists": lists }))

    @app.route('/worlds')
    def realmsworlds():
        mineOnlineServers = list(mongo.db.classicservers.find())
        featuredServers = list(mongo.db.featuredservers.find())
        featuredServers = [dict(server, **{'isMineOnline': False}) for server in featuredServers]
        servers = mineOnlineServers + featuredServers

        serverCount = mongo.db.classicservers.count_documents({})
        usersCount = 0
        privateCount = 0
        for server in servers:
            if 'users' in server:
                usersCount = usersCount + int(server['users'])
            if 'public' in server and  server['public'] == "false":
                privateCount = privateCount + 1
            if not 'players' in server:
                server['players'] = []

        def mapServer(x): 
            if (not "md5" in x):
                return
            if (not "whitelisted" in x):
                return
            if (not "realmId" in x):
                return

            if ("public" in x and x["public"] == False):
                return

            status = NONE

            if (x["onlinemode"] == False):
                status = OFFLINEMODE
            
            if (x["whitelisted"] == True):
                status = WHITELISTED

            playerUUIDs = []
            users = mongo.db.users
            for player in server["players"]:
                try:
                    playerData = users.find_one({"user": player})
                    playerUUIDs.append({
                        "uuid": playerData["uuid"].replace("-", ""),
                        "name": player,
                        "operator": True if playerData["uuid"] == server["ownerUUID"] else False,
                        "accepted": True,
                        "online": True,
                        "permission": "MEMBER"
                    })
                except:
                    pass

            if server["whitelisted"] == True and "whitelistUsers" in server and "whitelistUUIDS" in server:
                # If a player is not in the server but is whitelisted.
                for player in server["whitelistUsers"]:
                    try:
                        if player in server["players"]:
                            continue
                        playerData = users.find_one({"user": player})
                        playerUUIDs.append({
                            "uuid": playerData["uuid"].replace("-", ""),
                            "name": player,
                            "operator": True if playerData["uuid"] == server["ownerUUID"] else False,
                            "accepted": True,
                            "online": False,
                            "permission": "MEMBER"
                        })
                    except:
                        pass

                for playerUUID in server["whitelistUUIDs"]:
                    try:
                        playerData = users.find_one({"uuid": str(UUID(playerUUID))})
                        if playerData["user"] in server["players"] or playerData["user"] in server["whitelistUsers"]:
                            continue
                        playerUUIDs.append({
                            "uuid": playerData["uuid"].replace("-", ""),
                            "name": player,
                            "operator": True if playerData["uuid"] == server["ownerUUID"] else False,
                            "accepted": True,
                            "online": False,
                            "permission": "MEMBER"
                        })
                    except:
                        pass

            return { 
                "id": x["realmId"],
                "remoteSubscriptionId":"aaaa0000bbbb1111cccc2222dddd3333",
                "owner":"Whitelisted" if status == WHITELISTED else "Offline-Mode" if status == OFFLINEMODE else "",
                "ownerUUID":"806f3493624332a29166b098a0b03fd0" if x["ownerUUID"] == None else x["ownerUUID"],
                "name":x["name"],
                "motd":x["versionName"] if "versionName" in x else "Unknown Version",
                "state":"OPEN",
                "daysLeft":696969,
                "expired":False,
                "expiredTrial":False,
                "worldType":"NORMAL",
                "players":playerUUIDs,
                "maxPlayers":x["maxUsers"] if "maxUsers" in x else "24",
                "minigameName":None,
                "minigameId":None,
                "minigameImage":None,
                "activeSlot":1,
                "slots":None,
                "member":False
            }

        servers = list(map(mapServer, servers))
        servers = list(filter(filterServer, servers))
        res = make_response(json.dumps({"servers":servers}))  
        res.mimetype = 'application/json'
        return res

    @app.route('/worlds/v1/<realmId>/join/pc')
    @app.route('/worlds/<realmId>/join')
    def joinRealm(realmId):
        realmId = int(realmId)

        classicservers = mongo.db.classicservers
        featuredservers = mongo.db.featuredservers

        server = classicservers.find_one({"realmId": realmId})

        if server is None:
            server = featuredservers.find_one({"realmId": realmId})

        if server is None:
            return Response("Realm not found.", 404)

        res = make_response(json.dumps({
            "address": server["ip"] + ":" + server["port"],
            "pendingUpdate": False
        }))
        res.mimetype = 'application/json'
        return res

    @app.route('/invites/pending')
    def realmInvites():
        res = make_response(json.dumps({
            "invites": [
                # {
                #     "invitationId": "21538412",
                #     "worldName": "Anything Crafting 2020",
                #     "worldDescription": "We're back!",
                #     "worldOwnerName": "720Pony",
                #     "worldOwnerUuid": "e75e2d263b724a93a3e7a2491f4c454f",
                #     "date": 1568125140562
                # }
            ]
        }))
        res.mimetype = 'application/json'
        return res