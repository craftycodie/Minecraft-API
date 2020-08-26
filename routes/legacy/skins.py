from flask import Response, request, make_response, abort
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4
import bcrypt

def register_routes(app, mongo):
    ''' legacy cloak route '''
    @app.route('/MinecraftCloaks/<username>.png')
    def cloak(username):
        try:
            user = mongo.db.users.find_one({ "user": username })
        except:
            return abort(404)

        if not user or not 'cloak' in user or not user['cloak']:
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