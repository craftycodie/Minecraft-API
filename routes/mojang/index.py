from flask import Response, request, make_response
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4
import bcrypt
from routes.mojang.session import register_routes as register_session_routes
from routes.mojang.textures import register_routes as register_textures_routes

''' Mojang API routes (mojang.com) '''
def register_routes(app, mongo):
    register_session_routes(app, mongo)
    register_textures_routes(app, mongo)

    @app.route('/profiles/minecraft', methods=["POST"])
    def postprofiles():
        responseData = []

        users = mongo.db.users

        for username in request.json:
            user = users.find_one({"user": username})
            if not user:
                continue
            responseData.append({
                "id": user["uuid"].replace("-", ""),
                "name": username
            })

        res = make_response(json.dumps(responseData))
        res.mimetype = 'application/json'
        return res

    @app.route('/1_6_has_been_released.flag', methods=["GET"])
    def release1_6_releasedflag():
        return Response("", 404)

    @app.route('/authenticate', methods = ["POST"])
    def authenticate():
        username = request.json['username']
        password = request.json['password']
        discordUserID = request.json["discordUserID"] if "discordUserID" in request.json else None

        users = mongo.db.users

        if username == "":
            return Response("Bad login")
        elif password == "":
            return Response("Bad login")
        elif not users.find_one({"user": username}):
            return Response("Bad login")
        else:
            try:
                user = users.find_one({"user": username})
                matched = bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8'))
                if not matched:
                    return Response("Bad login")
                if not user['premium']:
                    return Response("User not premium.")
                if user:
                    sessionId = ObjectId()
                    users.update_one({"_id": user["_id"]}, { "$set": { "sessionId": sessionId, "discordUserID": discordUserID } })
                    if (not "uuid" in user):
                        uuid = str(uuid4())
                        users.update_one({ "_id": user["_id"] }, { "$set": { "uuid": uuid } })
                        res = make_response(json.dumps({
                            "accessToken": str(sessionId),
                            "selectedProfile": {
                                "id": uuid,
                                "name": user["user"]
                            }
                        }))
                    else:
                        res = make_response(json.dumps({
                            "accessToken": str(sessionId),
                            "selectedProfile": {
                                "id": user["uuid"],
                                "name": user["user"]
                            }
                        }))
                    res.mimetype = 'application/json'
                    return res
                else:
                    return Response("Something went wrong, please try again!")
            except:
                return Response("Something went wrong, please try again!")

        return Response("Something went wrong, please try again!")