from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4, UUID
from routes.mineonline.skins import register_routes as register_skins_routes
from routes.mineonline.servers import register_routes as register_servers_routes
from routes.mineonline.worlds import register_routes as register_worlds_routes
import os
import bcrypt


def register_routes(app, mongo):
    register_skins_routes(app, mongo)
    register_servers_routes(app, mongo)
    register_worlds_routes(app, mongo)

    #Given a username, respond a user uuid.
    @app.route('/api/playeruuid/<username>')
    @app.route('/mineonline/playeruuid/<username>')
    def playeruuid(username):
        try:
            users = mongo.db.users
            user = users.find_one({"user": username})
            if not user:
                return abort(404)
            if (not "uuid" in user):
                uuid = str(uuid4())
                users.update_one({ "_id": user["_id"] }, { "$set": { "uuid": uuid } })
                return make_response(json.dumps({
                    "uuid": uuid
                }), 200)
            else:
                return make_response(json.dumps({
                    "uuid": user["uuid"]
                }), 200)
        except:
            return Response("Something went wrong!", 500)

    @app.route('/api/getmyip')
    @app.route('/mineonline/getmyip')
    def ipaddress():
        return make_response(json.dumps({
            "ip": request.remote_addr
        }), 200)

    @app.route('/api/versions')
    @app.route('/mineonline/versions')
    def versionsindex():
        indexJson = { "versions" : []}

        versionsPath = './public/versions/'

        for subdir, dirs, files in os.walk('./public/versions/'):
            for file in files:
                openFile = open(os.path.join(subdir, file))
                data = openFile.read().encode("utf-8")
                indexJson["versions"].append({
                    "name": file,
                    "url": os.path.join(subdir, file).replace(versionsPath, "/public/versions/").replace("\\", "/"),
                    "modified": os.path.getmtime(os.path.join(subdir, file)),
                })

        res = make_response(json.dumps(indexJson))
        res.mimetype = 'application/json'
        return res
        
    @app.route('/api/player/<uuid>/presence', methods=['GET'])
    @app.route('/mineonline/player/<uuid>/presence', methods=['GET'])
    def playerpresence(uuid):
        uuid = str(UUID(uuid))
        user = None

        presence = {}

        try:
            users = mongo.db.users
            user = users.find_one({"uuid" : uuid})
        except:
            return Response("User not found.", 404)

        if (user == None):
            return Response("User not found.", 404)

        try:
            servers = mongo.db.classicservers
            server = servers.find_one({"players": { "$all": [ user["user"] ]}})
            if server != None:
                presence = {
                    "server": {
                        "name": server["name"],
                        "versionName": server["versionName"],
                        "ip": server["ip"],
                        "port": server["port"]
                    },
                }
        except:
            pass

        res = make_response(json.dumps(presence))
        res.mimetype = 'application/json'
        return res

    @app.route('/api/login', methods = ["POST"])
    def apilogin():
        username = request.json['username']
        password = request.json['password']

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
                    users.update_one({"_id": user["_id"]}, { "$set": { "sessionId": sessionId } })
                    if (not "uuid" in user):
                        uuid = str(uuid4())
                        users.update_one({ "_id": user["_id"] }, { "$set": { "uuid": uuid } })
                        res = make_response(json.dumps({
                            "uuid": uuid,
                            "sessionId": str(sessionId)
                        }))
                    else:
                        res = make_response(json.dumps({
                            "uuid": user["uuid"],
                            "sessionId": str(sessionId)
                        }))
                    res.mimetype = 'application/json'
                    return res
                else:
                    return Response("Something went wrong, please try again!")
            except:
                return Response("Something went wrong, please try again!")

        return Response("Something went wrong, please try again!")