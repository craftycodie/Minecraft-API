from config import port, databaseUrl, dbname, secretkey
from flask import Flask, Response, request, send_from_directory, abort, send_file, render_template, redirect, url_for, make_response
import json
import os
import bcrypt
import re
from flask_pymongo import PyMongo
from flask import Response 
from bson import json_util
from bson.objectid import ObjectId

app = Flask(__name__,
            static_folder='public/',
            template_folder='templates')

app.config['MONGO_DBNAME'] = dbname
app.config['MONGO_URI'] = databaseUrl
app.config['UPLOAD_FOLDER'] = "public/MinecraftSkins"
ALLOWED_EXTENSIONS = ['png']

mongo = PyMongo(app)

latestVersion = "1589019440"

@app.route('/game/getversion', methods = ["POST"]) # Legacy
def getversion_old():
    return Response("Old version")

@app.route('/game/getversion.jsp', methods = ["POST"])
def getversion():
    username = request.form['user']
    password = request.form['password']
    # version = request.form['version']

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

@app.route('/game/joinserver') # Legacy
@app.route('/game/joinserver.jsp')
def joinserver():
    username = request.args.get('user')
    sessionId = request.args.get('sessionId')
    serverId = request.args.get('serverId')

    serverjoins = mongo.db.serverjoins

    user = None

    try:
        users = mongo.db.users
        user = users.find_one({"sessionId": ObjectId(sessionId), "user": username})

        if not user:
            return Response("Invalid Session")
        if not user['premium']:
            return Response("User not premium.")

        serverjoins.delete_many({"user": username})

        serverjoins.insert_one({
            "user": username,
            "serverId": serverId,
        })

        response = Response("ok")
        return response
    except:
        return Response("Something went wrong.")

    return Response("Something went wrong.")

@app.route('/login/session.jsp')
def checksession():
    username = request.args.get('name')
    sessionId = request.args.get('session')

    user = None
    
    try:
        users = mongo.db.users
        user = users.find_one({"sessionId": ObjectId(sessionId), "user": username})

        if user and user['premium']:
            response = Response("ok")
            return response
        else:
            return make_response("Invalid Session", 400)
    except:
        return make_response("Invalid Session", 400)

    return make_response("Invalid Session", 400)

@app.route('/game/checkserver') # Legacy
@app.route('/game/checkserver.jsp')
def checkserver():
    username = request.args.get('user')
    serverId = request.args.get('serverId')

    serverjoins = mongo.db.serverjoins

    try:
        found = serverjoins.find_one({"user": username, "serverId": serverId})
        if not found:
            return make_response("Invalid Session", 401)

        serverjoins.delete_one({"_id": found['_id']})

        response = Response("YES")
        return response
    except:
        return Response("Invalid Session", 401)

    return Response("Invalid Session", 401)

@app.route('/skin/<username>.png') # classic
@app.route('/MinecraftSkins/<username>.png')
def skin(username):
    if username != "" and os.path.exists("public/MinecraftSkins/" + username + ".png"):
        return send_file("public/MinecraftSkins/" + username + ".png", mimetype="image/png")
    else:
        return abort(404)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/profile/', methods=['POST'])
def uploadSkin():
    user = None

    if 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
        try:
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(request.cookies['sessionId'])})
        except:
            pass
    else: 
        return redirect('/login.jsp')

    # check if the post request has the file part
    if 'file' not in request.files:
        return render_template("private/profile.html", error="Something went wrong.", user=user)
    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return render_template("private/profile.html", error="No file selected.", user=user)
    if file and allowed_file(file.filename):
        filename = user['user'] + ".png"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return render_template("private/profile.html", user=user)

    return render_template("private/profile.html", error="Invalid file.", user=user)

@app.route('/MinecraftDownload/minecraft.jar')
def downloadgame():
    username = request.args.get('user')
    downloadTicket = request.args.get('ticket')
    return send_file("public/MinecraftDownload/minecraft.jar")

@app.route('/resources/') # classic
@app.route('/MinecraftResources/')
def resourcesTree():
    username = request.args.get('user')
    downloadTicket = request.args.get('ticket')
    return send_file("public/MinecraftResources/download.xml")


@app.route('/register.jsp', methods = ["POST"])
def register():
    users = mongo.db.users

    if request.form['password1'] == "" or request.form['password2'] == "":
        return render_template("public/register.html", error="Please enter a password.")
    elif request.form['username'] == "":
        return render_template("public/register.html", error="Please enter a username.")
    elif request.form['email'] == "":
        return render_template("public/register.html", error="Please enter an E-mail address.")
    elif not re.compile(r"[^@]+@[^@]+\.[^@]+").match(request.form['email']):
        return render_template("public/register.html", error="Please enter a valid E-mail address.")
    elif request.form['password1'] != request.form['password2']:
        return render_template("public/register.html", error="Passwords don't match.")
    elif users.find_one({"user": request.form['username']}):
        return render_template("public/register.html", error="Username already exists.")
    elif users.find_one({"email": request.form['email']}):
        return render_template("public/register.html", error="E-Mail already exists.")
    else:
        try:
            hashpass = bcrypt.hashpw(request.form['password1'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            sessionId = ObjectId()
            inserted = users.insert_one({
                "user": request.form['username'],
                "email": request.form['email'],
                "password": hashpass,
                "premium": True, # TODO: Mojang Auth, actually check this.
                "sessionId": sessionId,
            })
            user = users.find_one({"_id": ObjectId(inserted.inserted_id)})
            if user:
                return render_template("public/register.html", sessionId=str(sessionId))
            else:
                return render_template("public/register.html", error="Something went wrong, please try again!")
        except:
            return render_template("public/register.html", error="Something went wrong, please try again!")

    return render_template("public/register.html", error="Something went wrong, please try again!")

@app.route('/login.jsp', methods = ["POST"])
def loginpost():
    users = mongo.db.users

    if request.form['username'] == "":
        return render_template("public/login.html", error="Please enter a username.")
    elif request.form['password'] == "":
        return render_template("public/login.html", error="Please enter your password.")
    elif not users.find_one({"user": request.form['username']}):
        return render_template("public/login.html", error="User does not exist.")
    else:
        try:
            user = users.find_one({"user": request.form['username']})
            matched = bcrypt.checkpw(request.form['password'].encode('utf-8'), user['password'].encode('utf-8'))
            if not matched:
                return render_template("public/login.html", error="Incorrect password.")
            if user:
                sessionId = ObjectId()
                users.update_one({"_id": user["_id"]}, { "$set": { "sessionId": sessionId } })
                return render_template("public/login.html", sessionId=str(sessionId))
            else:
                return render_template("public/login.html", error="Something went wrong, please try again!")
        except:
            return render_template("public/login.html", error="Something went wrong, please try again!")

    return render_template("public/login.html", error="Something went wrong, please try again!")

@app.route('/login.jsp')
def login():
    user = None

    if 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
        try:
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(request.cookies['sessionId'])})
            if not user:
                return serve('login')
            return redirect('/profile/')
        except:
            return redirect('/login/')
    return serve('login')

@app.route('/logout.jsp')
def logout():
    try:
        if 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
            users = mongo.db.users
            users.update_one({"sessionId": ObjectId(request.cookies['sessionId'])}, { "$set": { "sessionId": "" } })
    except:
        pass

    return redirect("/")


@app.route('/')
def index():
    return serve("index.jsp")

@app.route('/profile/')
def profile():
    return serve("profile")

@app.route('/support/')
def support():
    return serve("profile")

@app.route('/play.jsp')
def classic():
    user = None
    sessionIdInvalid = False
    serverIP = request.args.get('server')
    serverPort = request.args.get('port')

    path = path.replace(".jsp", "")

    if 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
        try:
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(request.cookies['sessionId'])})
            if not user:
                sessionIdInvalid = True
        except:
            pass

    return render_template("public/" + path + ".html", user=user, serverIP=serverIP, serverPort=serverPort, sessionIdInvalid=sessionIdInvalid)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
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
            return render_template("private/" + path + ".html", user=user, latestVersion=latestVersion)
        else:
            return redirect('/login.jsp')
    elif os.path.exists("templates/public/" + path + ".html"):
        return render_template("public/" + path + ".html", user=user, latestVersion=latestVersion)
    elif os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)

    return abort(404)





if __name__ == '__main__':
    app.secret_key = secretkey
    app.run(host= '0.0.0.0', port=port, debug=True)