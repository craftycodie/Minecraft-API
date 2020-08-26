from flask import Response, request, make_response
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4, UUID
from datetime import datetime
import time
import base64

''' Session server routes (sessionserver.mojang.com) '''
def register_routes(app, mongo):

    @app.route('/session/minecraft/profile/<uuid>')
    def sessionProfile(uuid):
        uuid = str(UUID(uuid))

        try:
            users = mongo.db.users
            user = users.find_one({"uuid": uuid})

            if user:
                profile = {
                        "timestamp": int(round(time.time() * 1000)),
                        "profileId": user["uuid"].replace("-", ""),
                        "profileName": user["user"],
                        "textures": {
                            "SKIN": { }
                        }
                }

                if "unsigned" in request.args and request.args["unsigned"] == "false":
                    profile["signatureRequired"] = True

                if "cloak" in user:
                    profile["textures"]["CAPE"] = {
                        "url": "http://mineonline.codie.gg/cloak/" + user["uuid"] + "/" + hashlib.md5(user["cloak"]).hexdigest()
                    }

                if "skin" in user:
                    profile["textures"]["SKIN"]["url"] = "http://mineonline.codie.gg/skin/" + user["uuid"] + "/" + hashlib.md5(user["skin"]).hexdigest()

                if "slim" in user and user["slim"]:
                    profile["textures"]["SKIN"]["metadata"] = { "model": "slim" }

                profile = json.dumps(profile)

                profile = str(base64.b64encode(profile.encode("utf-8")), "utf-8")

                res = {
                    "id" : user["uuid"].replace("-", ""),
                    "name" : user["user"],
                    "properties": [ 
                        {
                            "name": "textures",
                            "value": profile,
                        }
                    ],
                }

                if "unsigned" in request.args and request.args["unsigned"] == "false":
                    res["properties"][0]["signature"] = "wMtWktUN2RsPewNxAl2+sV/zuZQh03uG2Sf1KXlr2U6W8Zq63qiffvPNfF25KekP7CYogTEgCY4nfLgVUvy+FO4mdH1sg2D0qJ53pBCCdy8Uoq0XOZYrxtqrH5GhF0naH7kKuc8tjyMQ26sgIONUPGJpfJl1iWstRc30ilv78Gx+1oQullQX6lYYvbSZ0iIh6NI+2QkVJDJ4jl3H1ttLVYHldtFQO0IQLH3Yx/QGG/svD+TGMFdgDhIyGRDC4T+yty4uqEbUj25cfhrAL8uJWCa6TFOIeVbqdwldJb9uBFOqctezOT/GehETieNWEQ+zO9MH2R7F/KWYSfwFlIJF94CmCZoRe12LjIFn5NA7lUeQu0mqCoXeoRVfTi/po4ZOoV2nYSBz9KgXhCIz+NtxYIv51Lb1daSViz33tXvP+mJBU7EJlVYVPwNoSnO3KZZNB4WVElt4cEWOZV1J2hVr7uYXzxx9tV20PsiSw4dcwr0g0LcwEMVO9lA1r6rMOHxJ1z9cJ39FQKMU4nrB+OMXIRySrcadsS4ykfr1+EGqfTuxqGmy8h2DiahQvUIoKpntg2feGB7GI5inNWM1kFjN3rKa3XEa7grvfK1TwMP5CHUNwT5LQdtdng4j6kiu1U8xTWxieFAY8asUIX4KW63GFTJyMn2KZRRZTAhQd5D0UaA="

                res = make_response(json.dumps(res))
                res.mimetype = 'application/json'
                return res
            else:
                return Response("User not found.", 404)
        except:
            return Response("User not found.", 404)

    @app.route('/session/minecraft/join', methods=["POST"])
    def joinSession():
        sessionId = request.json["accessToken"]
        uuid = str(UUID(request.json["selectedProfile"]))
        serverId = request.json["serverId"]

        serverjoins = mongo.db.serverjoins

        user = None

        try:
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(sessionId), "uuid": uuid})

            if not user:
                res =  make_response(json.dumps({"errorMessage": "Invalid Session"}), 401)
                res.mimetype = 'application/json'
                return res
            if not user['premium']:
                res =  make_response(json.dumps({"errorMessage": "User not premium"}), 401)
                res.mimetype = 'application/json'
                return res

            serverjoins.delete_many({"playerUuid": uuid})

            serverjoins.insert_one({
                "createdAt": datetime.utcnow(),
                "playerName": user["user"],
                "playerUuid": user["uuid"],
                "serverId": serverId,
            })

            response = Response(None, 204)
            return response
        except:
            res =  make_response(json.dumps({"errorMessage": "Invalid Session"}), 401)
            res.mimetype = 'application/json'
            return res

        return make_response(json.dumps({"errorMessage": "Something went wrong."}), 401)

    @app.route('/blockedservers')
    def blockedservers():
        return Response("", 200)

    @app.route('/session/minecraft/hasJoined')
    def hasJoined():
        username = request.args.get('username')
        serverId = request.args.get('serverId')

        serverjoins = mongo.db.serverjoins
        users = mongo.db.users

        try:
            found = serverjoins.find_one({"playerName": username, "serverId": serverId})

            if not found:
                return Response("Invalid Session", 401)

            serverjoins.delete_one({"_id": found['_id']})

            user = users.find_one({"uuid": found["playerUuid"], "user": found["playerName"]})

            if not user:
                return Response("Invalid Session", 401)

            profile = {
                    "timestamp": int(round(time.time() * 1000)),
                    "profileId": user["uuid"].replace("-", ""),
                    "profileName": user["user"],
                    "signatureRequired": True,
                    "textures": {
                        "SKIN": { }
                    }
            }

            if "unsigned" in request.args and request.args["unsigned"] == "false":
                profile["signatureRequired"] = True

            if "cloak" in user:
                profile["textures"]["CAPE"] = {
                    "url": "http://mineonline.codie.gg/cloak/" + user["uuid"] + "/" + hashlib.md5(user["cloak"]).hexdigest()
                }

            if "skin" in user:
                profile["textures"]["SKIN"]["url"] = "http://mineonline.codie.gg/skin/" + user["uuid"] + "/" + hashlib.md5(user["skin"]).hexdigest()

            if "slim" in user and user["slim"]:
                profile["textures"]["SKIN"]["metadata"] = { "model": "slim" }

            profile = json.dumps(profile, indent=2)

            profile = str(base64.b64encode(profile.encode("utf-8")), "utf-8")

            res = {
                "id" : user["uuid"].replace("-", ""),
                "name" : user["user"],
                "properties": [ 
                    {
                        "name": "textures",
                        "value": profile,
                        "signature": "wMtWktUN2RsPewNxAl2+sV/zuZQh03uG2Sf1KXlr2U6W8Zq63qiffvPNfF25KekP7CYogTEgCY4nfLgVUvy+FO4mdH1sg2D0qJ53pBCCdy8Uoq0XOZYrxtqrH5GhF0naH7kKuc8tjyMQ26sgIONUPGJpfJl1iWstRc30ilv78Gx+1oQullQX6lYYvbSZ0iIh6NI+2QkVJDJ4jl3H1ttLVYHldtFQO0IQLH3Yx/QGG/svD+TGMFdgDhIyGRDC4T+yty4uqEbUj25cfhrAL8uJWCa6TFOIeVbqdwldJb9uBFOqctezOT/GehETieNWEQ+zO9MH2R7F/KWYSfwFlIJF94CmCZoRe12LjIFn5NA7lUeQu0mqCoXeoRVfTi/po4ZOoV2nYSBz9KgXhCIz+NtxYIv51Lb1daSViz33tXvP+mJBU7EJlVYVPwNoSnO3KZZNB4WVElt4cEWOZV1J2hVr7uYXzxx9tV20PsiSw4dcwr0g0LcwEMVO9lA1r6rMOHxJ1z9cJ39FQKMU4nrB+OMXIRySrcadsS4ykfr1+EGqfTuxqGmy8h2DiahQvUIoKpntg2feGB7GI5inNWM1kFjN3rKa3XEa7grvfK1TwMP5CHUNwT5LQdtdng4j6kiu1U8xTWxieFAY8asUIX4KW63GFTJyMn2KZRRZTAhQd5D0UaA="
                    }
                ]
            }

            res = make_response(json.dumps(res))
            res.mimetype = 'application/json'
            return res
        except:
            return Response("Invalid Session", 401)

        return Response("Invalid Session", 401)