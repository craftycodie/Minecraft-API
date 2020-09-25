from flask import Response, request, make_response
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4
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