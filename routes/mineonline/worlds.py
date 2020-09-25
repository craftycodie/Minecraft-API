from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4, UUID
from utils.modified_utf8 import utf8m_to_utf8s, utf8s_to_utf8m
from io import BytesIO, StringIO

def register_routes(app, mongo):
    #Deletes a users cloak.
    @app.route('/player/<uuid>/worlds/<worldId>')
    @app.route('/mineonline/player/<uuid>/worlds/<worldId>')
    def getWorld(uuid, worldId):
        uuid = str(UUID(uuid))
        maps = None
        mapId = str(int(worldId) - 1)

        try:
            users = mongo.db.users
            user = users.find_one({"uuid" : uuid})
        except:
            return Response("User not found.", 404)

        if (user == None):
            return Response("User not found.", 404)

        if 'maps' in user:
            maps = user['maps']
        else:
            return Response("Map not found.", 404)

        if mapId in maps:
            response = Response(maps[mapId]['data'], mimetype='application/x-mine')
            response.headers["content-disposition"] = "attachment; filename=" + maps[mapId]["name"] + ".mine"
            return response
        else:
            return Response("Map not found.", 404)