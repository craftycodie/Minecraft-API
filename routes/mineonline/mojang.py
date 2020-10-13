from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4, UUID
from utils.modified_utf8 import utf8m_to_utf8s, utf8s_to_utf8m
from PIL import Image, PngImagePlugin, ImageOps
from io import BytesIO, StringIO
import requests
import base64

def register_routes(app, mongo):
    @app.route('/api/stub/ok')
    def stubok():
        return Response("ok")

    # Classic authentication route.
    # Modified for mineonline.
    @app.route('/api/mojang/servertoken')
    def getmojangmmpass():
        sessionId = request.args['sessionId']
        serverIP = request.args['serverIP']
        serverPort = request.args['serverPort']
        uuid = request.args['uuid']

        try:
            server = mongo.db.classicservers.find_one({"ip": serverIP, "port": serverPort})
        except:
            return Response("Server not found.", 404)

        return abort(500)

        # Validate Token
        # Get username

        # if server:
        #     if "salt" in server:
        #         mppass = str(hashlib.md5((server['salt'] + username).encode('utf-8')).hexdigest())
        #         return Response(mppass)
        #     else:
        #         return Response("Classic server not found.", 404)
        # else:
        #     return Response("Server not found.", 404)

        # return Response("Something went wrong!", 500)

    @app.route('/api/mojang/player/<uuid>/skin/metadata', methods=['GET'])
    def mojangskinmetadata(uuid):
        uuid = str(UUID(uuid))
        return abort(404)

    @app.route('/api/mojang/player/<uuid>/skin/metadata', methods=['POST'])
    def mojangupdateskinmetadata(uuid):
        return abort(500)

    @app.route('/api/mojang/player/<uuid>/skin', methods=['POST'])
    def savemojangskin(uuid):
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

        return abort(500)

    ''' legacy cloak route '''
    @app.route('/mojang/MinecraftCloaks/<username>.png')
    def mojanglegacycloak(username):
        try:
            profile = json.loads(requests.get("https://api.mojang.com/users/profiles/minecraft/" + username).content)
            profile = json.loads(requests.get("https://sessionserver.mojang.com/session/minecraft/profile/" + profile["id"]).content)
            skinUrl = json.loads(base64.b64decode(profile["properties"][0]["value"]))["textures"]["CAPE"]["url"]
            skinBytes = BytesIO(requests.get(skinUrl).content)
            skinBytes.flush()
            skinBytes.seek(0)

            response = Response(skinBytes.read(), mimetype="image/png")
            
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            response.headers['Cache-Control'] = 'public, max-age=0'

            return response
        except Exception as e:
            return abort(404)

    ''' a different legacy cloak route '''
    @app.route('/mojang/cloak/get.jsp')
    def mojangbetaCloak():
        return mojanglegacycloak(request.values["user"])

    @app.route('/api/mojang/player/<uuid>/cloak', methods=['GET'])
    def mojangcloak(uuid):
        try:
            profile = json.loads(requests.get("https://sessionserver.mojang.com/session/minecraft/profile/" + uuid).content)
            skinUrl = json.loads(base64.b64decode(profile["properties"][0]["value"]))["textures"]["CLOAK"]["url"]
            skinBytes = BytesIO(requests.get(skinUrl).content)
            skinBytes.flush()
            skinBytes.seek(0)

            response = Response(skinBytes.read(), mimetype="image/png")
            
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            response.headers['Cache-Control'] = 'public, max-age=0'

            return response
        except Exception as e:
            return abort(404)

    @app.route('/api/mojang/player/<uuid>/skin', methods=['GET'])
    def mojangskin(uuid):
        try:
            profile = json.loads(requests.get("https://sessionserver.mojang.com/session/minecraft/profile/" + uuid).content)
            skinUrl = json.loads(base64.b64decode(profile["properties"][0]["value"]))["textures"]["SKIN"]["url"]
            skinBytes = BytesIO(requests.get(skinUrl).content)
            skinBytes.flush()
            skinBytes.seek(0)

            response = Response(skinBytes.read(), mimetype="image/png")
            
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            response.headers['Cache-Control'] = 'public, max-age=0'

            return response
        except Exception as e:
            return abort(404)

    @app.route('/mojang/skin/<username>.png') # classic
    @app.route('/mojang/MinecraftSkins/<username>.png')
    def mojanglegacyskin(username):
        try:
            profile = json.loads(requests.get("https://api.mojang.com/users/profiles/minecraft/" + username).content)
            profile = json.loads(requests.get("https://sessionserver.mojang.com/session/minecraft/profile/" + profile["id"]).content)
            skinUrl = json.loads(base64.b64decode(profile["properties"][0]["value"]))["textures"]["SKIN"]["url"]
            skinBytes = BytesIO(requests.get(skinUrl).content)
            skinBytes.flush()
            skinBytes.seek(0)
            skin = Image.open(skinBytes)
            croppedSkin = BytesIO()
            skin = skin.crop((0, 0, 64, 32))
            skin.save(croppedSkin, "PNG")
            skinBytes.flush()
            croppedSkin.seek(0)

            response = Response(croppedSkin.read(), mimetype="image/png")
            
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            response.headers['Cache-Control'] = 'public, max-age=0'

            return response
        except Exception as e:
            return abort(404)