from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from utils.servers import *
from bson.objectid import ObjectId
from uuid import UUID

def register_routes(app, mongo):
    # Checks for valid realms management authorization.
    def getAuthorizedUserAndServer(realmId):
        [sessionID, userUuid] = str.split(request.cookies.get("sid").replace("token:", ""), ":")
        username = request.cookies.get("user")

        if(sessionID == None):
            abort(401)

        server = None
        try:
            server = mongo.db.classicservers.find_one({"realmId": int(realmId)})
        except:
            abort(404)

        if(server == None):
            abort(404)

        user = None
        try:
            user = mongo.db.users.find_one({"user": username, "sessionId": ObjectId(sessionID), "uuid": userUuid})
        except:
            abort(404)

        if(user == None or user["user"] != server["owner"]):
            abort(401)

        return [user, server]

    @app.route('/worlds/<realmId>')
    def realmsworld(realmId):
        [user, server] = getAuthorizedUserAndServer(realmId)

        if (not "md5" in server):
            abort(404)
        if (not "whitelisted" in server):
            abort(404)

        status = NONE

        if (server["onlinemode"] == False):
            status = OFFLINEMODE
        
        if (server["whitelisted"] == True and "whitelistUsers" in server and "whitelistIPs" in server and "whitelistedUUIDs" in server):
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
            "id": server["realmId"],
            "remoteSubscriptionId": "aaaa0000bbbb1111cccc2222dddd3333",
            "owner": "Whitelisted" if status == WHITELISTED else "Offline-Mode" if status == OFFLINEMODE else "",
            "ownerUUID": "806f3493624332a29166b098a0b03fd0" if server["ownerUUID"] == None else server["ownerUUID"],
            "name": server["name"],
            "motd": server["versionName"] if "versionName" in server else "Unknown Version",
            "state": "OPEN",
            "daysLeft": 696969,
            "expired": False,
            "expiredTrial": False,
            "worldType": "NORMAL",
            "players": playerUUIDs,
            "maxPlayers": server["maxUsers"] if "maxUsers" in server else "24",
            "minigameName": None,
            "minigameId": None,
            "minigameImage": None,
            "activeSlot": 1,
            "slots": None,
            "member": False
        }

        res = make_response(json.dumps(server))  
        res.mimetype = 'application/json'
        return res

    @app.route('/invites/<realmID>', methods=["POST"])
    def inviteUser(realmID):
        [user, server] = getAuthorizedUserAndServer(realmID)
        
        res = make_response(json.dumps({"errorMessage": "Not yet implemented."}), 501)
        res.mimetype = 'application/json'
        return res

    @app.route('/invites/<realmID>/invite/<playerUUID>', methods=["DELETE"])
    def uninviteUser(realmID, playerUUID):
        [user, server] = getAuthorizedUserAndServer(realmID)
        
        res = make_response(json.dumps({"errorMessage": "Not yet implemented."}), 501)
        res.mimetype = 'application/json'
        return res

    #returns { "ops": ["playerNames"] }
    @app.route('/ops/<realmID>/<playerUUID>', methods=["POST"])
    def opUser(realmID, playerUUID):
        [user, server] = getAuthorizedUserAndServer(realmID)
        
        res = make_response(json.dumps({"errorMessage": "Not yet implemented."}), 501)
        res.mimetype = 'application/json'
        return res

    @app.route('/ops/<realmID>/<playerUUID>', methods=["DELETE"])
    def deopUser(realmID, playerUUID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        res = make_response(json.dumps({"errorMessage": "Not yet implemented."}), 501)
        res.mimetype = 'application/json'
        return res

    @app.route('/worlds/<realmID>/close', methods=["PUT"])
    def stopServer(realmID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        res = make_response(json.dumps({"errorMessage": "Not yet implemented."}), 501)
        res.mimetype = 'application/json'
        return res

    @app.route('/worlds/<realmID>', methods=["POST"])
    def renameServer(realmID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        return Response("Not yet implemented.", 501)

    @app.route('/subscriptions/<realmID>')
    def subscription(realmID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        res = make_response(json.dumps({
            "startDate": 0,
            "daysLeft": 0,
            "subscriptionType": "RECURRING"
        }))
        res.mimetype = 'application/json'
        return res

    @app.route('/worlds/<realmID>/slot/<slotID>', methods=["PUT"])
    def createWorld(realmID, slotID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        return Response("Not yet implemented.", 501)

    @app.route('/worlds/<realmID>/reset', methods=["POST"])
    def resetWorld(realmID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        return Response("Not yet implemented.", 501)

    @app.route('/worlds/<realmID>/slot/<slotID>', methods=["POST"])
    def editWorld(realmID, slotID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        return Response("Not yet implemented.", 501)

    @app.route('/worlds/<realmID>/backups')
    def worldBackups(realmID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        res = make_response(json.dumps({
            "backups": [
                # {
                #     "backupId": "2019-09-08T18:04:53.5284117Z",
                #     "lastModifiedDate": 1567965893000,
                #     "size": 11080009,
                #     "metadata": {
                #         "game_difficulty": "1",
                #         "name": "Azerus Team",
                #         "game_server_version": "1.14.4",
                #         "enabled_packs": "{\"resourcePacks\":[],\"behaviorPacks\":[]}",
                #         "description": "§7Creators of §6Puzzle Wars§7 and §6Maze Wars              §8(l’o’l)",
                #         "game_mode": "0",
                #         "world_type": "NORMAL"
                #     }
                # }
            ]
        }))
        res.mimetype = 'application/json'
        return res

    @app.route('/worlds/<realmID>/slot/<slotID>/download')
    def downloadLatestBackup(realmID, slotID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        # res = make_response(json.dumps({
        #     "downloadLink": "http://us-west-mcr-worlds.s3.amazonaws.com/dfasdfa/mcr_world.tar.gz?AWSAccessKeyId=ADSFASDFADSF&Expires=1457647137&Signature=ADSFASDFASDF",
        #     "resourcePackUrl": None,
        #     "resourcePackHash": None
        # }))
        # res.mimetype = 'application/json'
        # return res

        return Response("Not yet implemented.", 501)

    @app.route('/worlds/<realmID>/backups', methods=["PUT"])
    def restoreBackup(realmID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        backupId = request.args["backupId"]

        return Response("Not yet implemented.", 501)

    @app.route('/worlds/<realmID>/slot/<slotID>', methods=["PUT"])
    def uploadWorld(realmID, slotID):
        [user, server] = getAuthorizedUserAndServer(realmID)

        return Response("Not yet implemented.", 501)

    @app.route('/worlds/templates/<templateType>')
    def getWorldTemplates(templateType):
        if int(request.args["page"]) > 1:
            return Response("", 404)
        res = make_response(json.dumps({
            "templates": [
                {
                    "id": 1,
                    "name": "No templates yet, but here's a song I made!",
                    "version": None,
                    "author": "Codie",
                    "link": "https://open.spotify.com/track/1St1PsxfQB6EOfI9ypHYAi?si=Fsmas2MgQoyl7DI0mbEcDg",
                    "image": None,
                    "trailer": "https://www.youtube.com/watch?v=OnYOzTwMQFY",
                    "recommendedPlayers": "2+ players",
                    "type": "MINIGAME"
                },
                {
                    "id": 1,
                    "name": "Hi yes me tweet!",
                    "version": None,
                    "author": "@codieradical",
                    "link": "https://twitter.com/codieradical",
                    "image": None,
                    "trailer": None,
                    "recommendedPlayers": "2+ players",
                    "type": "MINIGAME"
                }
            ],
            "page": 1,
            "size": 1,
            "total": 1
        }))
        res.mimetype = 'application/json'
        return res

        #return Response("Not yet implemented.", 501)