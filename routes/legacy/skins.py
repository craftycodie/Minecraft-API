from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4
import bcrypt
from io import BytesIO, StringIO
from PIL import Image, PngImagePlugin, ImageOps
import requests
import base64

def register_routes(app, mongo):
    ''' legacy cloak route '''
    @app.route('/MinecraftCloaks/<username>.png')
    def cloak(username):
        try:
            user = mongo.db.users.find_one({ "user": username })
        except:
            return abort(404)

        # use official skins for users not signed up to mineonline.
        if not user:
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
                print(e)
                abort(404)

        if not 'cloak' in user or not user['cloak']:
            return abort(404)

        response = Response(user['cloak'], mimetype="image/png")
        
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers['Cache-Control'] = 'public, max-age=0'

        return response

    ''' a different legacy cloak route '''
    @app.route('/cloak/get.jsp')
    def legacyCloak():
        return cloak(request.values["user"])

    @app.route('/skin/<username>.png') # classic
    @app.route('/MinecraftSkins/<username>.png')
    def skin(username):
        try:
            user = mongo.db.users.find_one({ "user": username })
        except:
            abort(404)

        # use official skins for users not signed up to mineonline.
        if not user:
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
                abort(404)
            

        if not 'skin' in user or not user['skin']:
            return abort(404)

        # Crop 64x64 skins to 64x32
        skinBytes = BytesIO(user['skin'])
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