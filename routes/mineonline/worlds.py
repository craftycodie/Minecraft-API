from flask import Response, request, make_response, abort, redirect
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4, UUID
from utils.modified_utf8 import utf8m_to_utf8s, utf8s_to_utf8m
from io import BytesIO, StringIO

def register_routes(app, mongo):
    # Download a classic world.
    @app.route('/player/<uuid>/world/<worldId>')
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

    # Website route: Delete a world then go back to the profile page.
    @app.route('/player/<uuid>/world/<worldId>/delete')
    def deleteWorldWebpage(uuid, worldId):
        if 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
            deleteWorld(uuid, worldId, request.cookies['sessionId'])
            return redirect('/profile/')
        else:
            return redirect('/login.jsp')

    @app.route('/player/<uuid>/world/<worldId>', methods = ["DELETE"])
    def deleteWorld(uuid, worldId, sessionId = None):
        uuid = str(UUID(uuid))
        maps = None
        mapId = str(int(worldId) - 1)

        if sessionId == None:
            sessionId = request.args["sessionId"] if "sessionId" in request.args else None

        if sessionId == None:
            return Response("You must be logged in to delete a world.", 401)

        try:
            users = mongo.db.users
            user = users.find_one({"uuid" : uuid, "sessionId": ObjectId(sessionId)})
        except:
            return Response("Invalid session.", 401)

        if (user == None):
            return Response("Invalid session.", 404)

        if 'maps' in user:
            maps = user['maps']
        else:
            # If the map doesn't exist it may have already been deleted, 200.
            return Response("ok", 200)

        maps.pop(mapId, None)
        users.update_one({"_id": user["_id"]}, {"$set": {"maps": maps}})

        return Response("ok", 200)