import codecs
from flask import request, abort, redirect, render_template, send_from_directory, Markup
import os
from markdown import markdown
from bson.objectid import ObjectId

readme_html = None
static_folder = None
mongo = None

def serve(path):
    global static_folder
    global mongo
    global readme_html

    user = None
    sessionIdInvalid = False

    path = path.replace(".jsp", "")
    path = path.replace("/resources/", "/MinecraftResources/")

    if 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
        try:
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(request.cookies['sessionId'])})
            if not user:
                sessionIdInvalid = True
        except:
            pass

    if path == "":
        return abort(404)

    if os.path.exists("templates/private/" + path + ".html"):
        if user:
            return render_template("private/" + path + ".html", user=user)
        else:
            return redirect('/login.jsp')
    elif os.path.exists("templates/public/" + path + ".html"):
        return render_template("public/" + path + ".html", user=user, readme_html=readme_html, args=request.args)
    elif os.path.exists(static_folder + '/' + path):
        return send_from_directory(static_folder, path)

    return abort(404)

def register_routes(app, _mongo):
    global readme_html
    global static_folder
    global mongo

    # These are imported after serve is defined.
    from routes.legacy import register_routes as register_legacy_routes
    from routes.mineonline import register_routes as register_mineonline_routes
    from routes.realms import register_routes as register_realms_routes
    from routes.mojang import register_routes as register_mojang_routes

    register_legacy_routes(app, _mongo)
    register_mineonline_routes(app, _mongo)
    register_realms_routes(app, _mongo)
    register_mojang_routes(app, _mongo)

    readme_file = codecs.open("README.md", mode="r", encoding="utf-8")
    readme_html = Markup(markdown(readme_file.read()))
    readme_file.close()
    static_folder = app.static_folder
    mongo = _mongo

    @app.route('/', defaults={'path': 'index'})
    @app.route('/<path:path>')
    def serveroute(path):
        return serve(path)
