from config import port, databaseUrl, dbname, secretkey
from flask import Flask, Response, request, send_from_directory, abort, send_file, render_template, redirect, url_for, make_response
import json
import os
import jwt
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

latestVersion = "1.0.0"

@app.route('/game/getversion', methods = ["POST"])
def getversion():
    username = request.form['user']
    password = request.form['password']

    downloadToken = "deprecated"

    users = mongo.db.users

    if username == "":
        return make_response("Bad login", 400)
    elif password == "":
        return make_response("Bad login", 400)
    elif not users.find_one({"user": username}):
        return make_response("Bad login", 400)
    else:
        try:
            user = users.find_one({"user": username})
            matched = bcrypt.hashpw(password.encode('utf-8'), user['password'].encode('utf-8')) == user['password']
            if matched:
                return make_response("Bad login", 400)
            if user:
                session = jwt.encode({
                    "id": str(user['_id']),
                    "user": user['user'],
                    "email": user['email'],
                    "owns_minecraft": user['owns_minecraft']
                }, secretkey, algorithm='HS256').decode('utf-8')
                downloadToken = "deprecated"
                response = Response(':'.join([latestVersion, downloadToken, username, session]))
                return response
            else:
                return make_response("Something went wrong, please try again!", 400)
        except:
            return make_response("Something went wrong, please try again!", 400)

    return make_response("Something went wrong, please try again!", 400)

@app.route('/game/joinserver')
def joinserver():
    username = request.args.get('user')
    sessionId = request.args.get('sessionId')
    serverId = request.args.get('serverId')

    serverjoins = mongo.db.serverjoins

    try:
        jwt.decode(sessionId.encode('utf-8'), secretkey, algorithm='HS256')

        serverjoins.delete_many({"user": username})

        serverjoins.insert_one({
            "user": username,
            "serverId": serverId,
        })

        response = Response("ok")
        return response
    except:
        return make_response("Invalid Session", 401)

    return make_response("Invalid Session", 401)

@app.route('/login/session')
def checksession():
    username = request.args.get('name')
    session = request.args.get('session')

    try:
        session = jwt.decode(session.encode('utf-8'), secretkey, algorithm='HS256')

        if session['owns_minecraft']:
            response = Response("ok")
            return response
        else:
            return make_response("Invalid Session", 400)
    except:
        return make_response("Invalid Session", 400)

    return make_response("Invalid Session", 400)

@app.route('/game/checkserver')
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
        return make_response("Invalid Session", 401)

    return make_response("Invalid Session", 401)


@app.route('/MinecraftSkins/<username>.png')
def skin(username):
    if username != "" and os.path.exists("public/MinecraftSkins/" + username + ".png"):
        return send_file("public/MinecraftSkins/" + username + ".png", mimetype="image/png")
    else:
        return abort(404)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/profile', methods=['POST'])
def uploadSkin():
    if 'jwt' in request.cookies:
        session = jwt.decode(request.cookies['jwt'].encode('utf-8'), secretkey, algorithm='HS256')
    else:
        return redirect('login')

    # check if the post request has the file part
    if 'file' not in request.files:
        return render_template("private/profile.html", error="Something went wrong.", session=session)
    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return render_template("private/profile.html", error="No file selected.", session=session)
    if file and allowed_file(file.filename):
        filename = session['user'] + ".png"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return render_template("private/profile.html", error="No file selected.", session=session)

@app.route('/MinecraftDownload/minecraft.jar')
def downloadgame():
    username = request.args.get('user')
    downloadTicket = request.args.get('ticket')
    return send_file("public/MinecraftDownload/minecraft.jar")

@app.route('/MinecraftResources/')
def resourcesTree():
    username = request.args.get('user')
    downloadTicket = request.args.get('ticket')
    return send_file("public/MinecraftResources/download.xml")


@app.route('/register', methods = ["POST"])
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
        # try:
            hashpass = bcrypt.hashpw(request.form['password1'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            inserted = users.insert_one({
                "user": request.form['username'],
                "email": request.form['email'],
                "password": hashpass,
                "owns_minecraft": True, # TODO: Mojang Auth, actually check this.
            })
            user = users.find_one({"_id": ObjectId(inserted.inserted_id)})
            if user:
                session = jwt.encode({
                    "id": str(user['_id']),
                    "user": user['user'],
                    "email": user['email'],
                    "owns_minecraft": user['owns_minecraft']
                }, secretkey, algorithm='HS256').decode('utf-8')
                return render_template("public/register.html", jwt=session)
            else:
                return render_template("public/register.html", error="Something went wrong, please try again!")
        # except:
        #     return render_template("public/register.html", error="Something went wrong, please try again!")

    return render_template("public/register.html", error="Something went wrong, please try again!")

@app.route('/login', methods = ["POST"])
def login():
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
            matched = bcrypt.hashpw(request.form['password'].encode('utf-8'), user['password'].encode('utf-8')) == user['password']
            if matched:
                return render_template("public/login.html", error="Incorrect password.")
            if user:
                session = jwt.encode({
                    "id": str(user['_id']),
                    "user": user['user'],
                    "email": user['email'],
                    "owns_minecraft": user['owns_minecraft']
                }, secretkey, algorithm='HS256').decode('utf-8')
                return render_template("public/login.html", jwt=session)
            else:
                return render_template("public/login.html", error="Something went wrong, please try again!")
        except:
            return render_template("public/login.html", error="Something went wrong, please try again!")

    return render_template("public/login.html", error="Something went wrong, please try again!")


@app.route('/')
def index():
    return serve("index")


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if 'jwt' in request.cookies:
        session = jwt.decode(request.cookies['jwt'].encode('utf-8'), secretkey, algorithm='HS256')
    else:
        session = None

    if path == "":
        return abort(404)

    if os.path.exists("templates/private/" + path + ".html"):
        if session:
            return render_template("private/" + path + ".html", session=session, latestVersion=latestVersion)
        else:
            return redirect('login')
    if os.path.exists("templates/public/" + path + ".html"):
        return render_template("public/" + path + ".html", session=session, latestVersion=latestVersion)
    if os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)

    return abort(404)





if __name__ == '__main__':
    app.secret_key = secretkey
    app.run(host= '0.0.0.0', port=port, debug=True)