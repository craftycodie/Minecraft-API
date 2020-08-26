from flask import Response, request, make_response
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4
from routes.mineonline.skins import register_routes as register_skins_routes
from routes.mineonline.servers import register_routes as register_servers_routes
import os


def register_routes(app, mongo):
    register_skins_routes(app, mongo)
    register_servers_routes(app, mongo)

    # Classic authentication route.
    # Modified for mineonline.
    @app.route('/mineonline/mppass.jsp')
    def getmmpass():
        sessionId = request.args['sessionId']
        serverIP = request.args['serverIP']
        serverPort = request.args['serverPort']

        try:
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(sessionId)})
        except:
            return Response("User not found.", 404)

        if (user == None):
            return Response("User not found.", 404)

        try:
            server = mongo.db.classicservers.find_one({"ip": serverIP, "port": serverPort})
        except:
            return Response("Server not found.", 404)

        if server:
            if "salt" in server:
                mppass = str(hashlib.md5((server['salt'] + user['user']).encode('utf-8')).hexdigest())
                return Response(mppass)
            else:
                return Response("Classic server not found.", 404)
        else:
            return Response("Server not found.", 404)

        return Response("Something went wrong!", 500)

    #Given a username, respond a user uuid.
    @app.route('/mineonline/playeruuid/<username>')
    def playeruuid(username):
        sessionId = request.args['session']
        if sessionId:
            try:
                users = mongo.db.users
                user = users.find_one({"sessionId": ObjectId(sessionId)})
                if not user:
                    return Response("Invalid session.", 400)
                if user["user"] != username:
                    return Response("Wrong username.", 400)
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

        return Response("You must be logged in to do this.", 401)

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