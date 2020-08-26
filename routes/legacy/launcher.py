from flask import Response, request, make_response, send_file
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4
import bcrypt

def register_routes(app, mongo):
    
    '''Old server login route.'''
    @app.route('/game/getversion.jsp', methods = ["POST"])
    def getversion():
        username = request.form['user']
        password = request.form['password']
        # This never seems to hold anything.
        # version = request.form['version']

        latestVersion = open("./public/MinecraftDownload/version", mode="r", encoding="utf-8")
        latestVersion = latestVersion.readline()

        downloadToken = "deprecated"

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
                    response = Response(" \n" + (':'.join([latestVersion, downloadToken, username, str(sessionId)])))
                    return response
                else:
                    return Response("Something went wrong, please try again!")
            except:
                return Response("Something went wrong, please try again!")

        # If the launcher is updated
        # res  "Old version"

        return Response("Something went wrong, please try again!")

    @app.route('/MinecraftDownload/minecraft.jar')
    def downloadgame():
        username = request.args.get('user')
        downloadTicket = request.args.get('ticket')
        return send_file("public/MinecraftDownload/minecraft.jar")