from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4, UUID
from utils.modified_utf8 import utf8m_to_utf8s, utf8s_to_utf8m
from PIL import Image, PngImagePlugin, ImageOps
from io import BytesIO, StringIO

def register_routes(app, mongo):
    #Deletes a users cloak.
    @app.route('/mineonline/removecloak.jsp')
    def removeCloak():
        sessionId = request.args['sessionId']

        if sessionId:
            try:
                users = mongo.db.users
                user = users.find_one({"sessionId": ObjectId(sessionId)})
                if not user:
                    return Response("Invalid session.", 400)
                users.update_one({ "_id": user["_id"] }, { "$set": { "cloak": "" } })
                return Response("ok", 200)
            except:
                return Response("Something went wrong!", 500)

        return Response("You must be logged in to do this.", 401)

    @app.route('/mineonline/player/<uuid>/skin/metadata', methods=['GET'])
    def mineonlineskinmetadata(uuid):
        uuid = str(UUID(uuid))
        try:
            user = mongo.db.users.find_one({ "uuid": uuid })
        except:
            return abort(404)
        if not user:
            return abort(404)

        return make_response(json.dumps({
            "slim": user["slim"]
        }))

    @app.route('/mineonline/player/<uuid>/skin/metadata', methods=['POST'])
    def mineonlineupdateskinmetadata(uuid):
        sessionId = request.args['session']
        if sessionId:
            try:
                users = mongo.db.users
                user = users.find_one({"uuid" : uuid, "sessionId": ObjectId(sessionId)})
            except:
                return Response("Invalid Session", 401)
        else:
            return Response(401)

        uuid = str(UUID(uuid))
        try:
            user = mongo.db.users.find_one({ "uuid": uuid })
        except:
            return abort(404)
        if not user:
            return abort(404)

        updates = {}

        if "slim" in request.json:
            updates["slim"] = request.json["slim"]

        users.update_one({ "_id": user["_id"] }, { "$set": updates })

        return Response(200)

    #mineonline
    @app.route('/mineonline/player/<uuid>/skin', methods=['POST'])
    def saveskin(uuid):
        uuid = str(UUID(uuid))
        sessionId = None

        user = None

        try:
            requestData = request.stream.read()

            sessionId_length = int.from_bytes(requestData[1 : 2], byteorder='big')
            sessionId = requestData[2 : 2 + sessionId_length]
            skinLength = int.from_bytes(requestData[2 + sessionId_length + 2: 2 + sessionId_length + 2 + 4], byteorder='big')
            skinData = requestData[2 + sessionId_length + 4 : len(requestData)]

            sessionId = str(utf8m_to_utf8s(sessionId), 'utf-8')

        except:
            return Response("Something went wrong!", 500)

        try:
            users = mongo.db.users
            user = users.find_one({"uuid" : uuid, "sessionId": ObjectId(sessionId)})
        except:
            return Response("Invalid Session", 401)

        if (user == None):
            return Response("Invalid Session", 401)

        try:
            skinBytes = BytesIO()
            skinBytes.write(skinData)
            skinBytes.flush()
            skinBytes.seek(0)
            skin = Image.open(skinBytes)
            croppedSkin = BytesIO()
            [width, height] = skin.size

            if (width < 64 or height < 32):
                return Response("Skin too small.", 400)
            elif (height < 64):
                skin = skin.crop((0, 0, 64, 32))
            elif (height >= 64 or width > 64):
                skin = skin.crop((0, 0, 64, 64))
        
            skin.save(croppedSkin, "PNG")
            skinBytes.flush()
            croppedSkin.seek(0)
            users.update_one({ "_id": user["_id"] }, { "$set": { "skin": croppedSkin.read() } })
        except:
            return Response("Failed to upload skin.", 500)

        return Response("ok")

    #mineonline
    @app.route('/mineonline/player/<uuid>/cloak', methods=['POST'])
    def savecloak(uuid):
        uuid = str(UUID(uuid))
        sessionId = None

        user = None

        try:
            requestData = request.stream.read()

            sessionId_length = int.from_bytes(requestData[1 : 2], byteorder='big')
            sessionId = requestData[2 : 2 + sessionId_length]
            cloakLength = int.from_bytes(requestData[2 + sessionId_length + 2: 2 + sessionId_length + 2 + 4], byteorder='big')
            cloakData = requestData[2 + sessionId_length + 4 : len(requestData)]

            sessionId = str(utf8m_to_utf8s(sessionId), 'utf-8')

        except:
            return Response("Something went wrong!", 500)

        try:
            users = mongo.db.users
            user = users.find_one({"uuid" : uuid, "sessionId": ObjectId(sessionId)})
        except:
            return Response("Invalid Session", 401)

        if (user == None):
            return Response("Invalid Session", 401)

        try:
            cloakBytes = BytesIO()
            cloakBytes.write(cloakData)
            cloakBytes.flush()
            cloakBytes.seek(0)
            cloak = Image.open(cloakBytes)
            croppedCloak = BytesIO()
            cloak = cloak.crop((0, 0, 64, 32))
            cloak.save(croppedCloak, "PNG")
            cloakBytes.flush()
            croppedCloak.seek(0)
            users.update_one({ "_id": user["_id"] }, { "$set": { "cloak": croppedCloak.read() } })
        except:
            return Response("Failed to upload skin.", 500)

        return Response("ok")