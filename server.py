from flask import Flask, Response, request, send_from_directory, abort, send_file, render_template, redirect, url_for, make_response, Markup
import json
import os
import bcrypt
import re
from flask_pymongo import PyMongo
from bson import json_util
from bson.objectid import ObjectId
from utils.modified_utf8 import utf8m_to_utf8s, utf8s_to_utf8m
from datetime import datetime
import hashlib
from markdown import markdown
import codecs
from flask_mail import Mail, Message
from threading import Thread
from PIL import Image, PngImagePlugin
from io import BytesIO, StringIO

# import config if present
try: import config
except: pass

app = Flask(__name__,
            static_folder='public/',
            template_folder='templates')

app.config['MONGO_DBNAME'] = os.getenv("MONGO_DBNAME")
app.config['MONGO_URI'] = os.getenv("MONGO_URI")
ALLOWED_EXTENSIONS = ['png']
secretkey = os.getenv("SECRET_KEY")
port = os.getenv("PORT", 80)

app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 465,
    MAIL_USE_TLS = False,
    MAIL_USE_SSL = True,
    MAIL_USERNAME = os.getenv("EMAIL_USER"),
    MAIL_PASSWORD = os.getenv("EMAIL_PASSWORD"),
))

mail = Mail(app)

mongo = PyMongo(app)
mongo.db.classicservers.create_index( "createdAt", expireAfterSeconds = 60)
mongo.db.serverjoins.create_index( "createdAt", expireAfterSeconds = 600 )
mongo.db.users.create_index("user", unique = True )
mongo.db.users.create_index("email", unique = True )

latestVersion = "1589019440"

readme_file = codecs.open("README.md", mode="r", encoding="utf-8")
readme_html = Markup(markdown(readme_file.read()))
readme_file.close()

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

@app.route('/game/joinserver.jsp')
def joinserver():
    username = request.args.get('user')
    sessionId = request.args.get('sessionId')
    serverId = request.args.get('serverId')

    if not 'sessionId' in request.args or sessionId == None:
        return Response("Invalid Session: you are not logged in.")

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
            "createdAt": datetime.utcnow(),
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
            return Response("ok")
        else:
            return Response("Invalid Session", 400)
    except:
        return Response("Invalid Session", 400)

    return Response("Invalid Session", 400)

@app.route('/game/checkserver.jsp')
def checkserver():
    username = request.args.get('user')
    serverId = request.args.get('serverId')

    serverjoins = mongo.db.serverjoins

    try:
        found = serverjoins.find_one({"user": username, "serverId": serverId})
        if not found:
            return Response("Invalid Session", 401)

        serverjoins.delete_one({"_id": found['_id']})

        response = Response("YES")
        return response
    except:
        return Response("Invalid Session", 401)

    return Response("Invalid Session", 401)

@app.route('/skin/<username>.png') # classic
@app.route('/MinecraftSkins/<username>.png')
def skin(username):
    try:
        user = mongo.db.users.find_one({ "user": username })
    except:
        return abort(404)

    if not user or not 'skin' in user or not user['skin']:
        return abort(404)

    response = Response(user['skin'], mimetype="image/png")
    
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers['Cache-Control'] = 'public, max-age=0'

    return response

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
    skinFile = request.files['file']
    cloakFile = request.files['cloak']

    if skinFile.filename == '' and cloakFile.filename == '':
        return render_template("private/profile.html", error="No file selected.", user=user)

    if skinFile and allowed_file(skinFile.filename):
        if skinFile.stream.tell() > 8096:
            return render_template("private/profile.html", error="Skin too large.", user=user)
        skinBytes = BytesIO()
        skinFile.save(skinBytes)
        skinBytes.flush()
        skinBytes.seek(0)
        skin = Image.open(skinBytes)
        croppedSkin = BytesIO()
        skin = skin.crop((0, 0, 64, 32))
        skin.save(croppedSkin, "PNG")
        skinBytes.flush()
        croppedSkin.seek(0)
        users.update_one({ "_id": user["_id"] }, { "$set": { "skin": croppedSkin.read() } })

    if cloakFile and allowed_file(cloakFile.filename):
        if cloakFile.stream.tell() > 4096:
            return render_template("private/profile.html", error="Cloak too large.", user=user)
        cloakBytes = BytesIO()
        cloakFile.save(cloakBytes)
        cloakBytes.flush()
        cloakBytes.seek(0)
        users.update_one({ "_id": user["_id"] }, { "$set": { "cloak": cloakBytes.read() } }) 

    return render_template("private/profile.html", user=user)

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


@app.route('/forgotpass.jsp', methods = ["POST"])
def forgotpass():
    username = request.form['username']
    email = request.form['email']

    url = request.host_url + 'changepass.jsp'
    users = mongo.db.users

    if not username and not email:
        return render_template("public/forgotpass.html", error="Please provide your username or email.")

    user = None
    if username:
        user = users.find_one({ "user": username })
    elif not user and email:
        user = users.find_one({ "email": email })
    if not user:
        return render_template("public/forgotpass.html", error="User not found.")

    resetToken = ObjectId()

    users.update_one({"_id": user["_id"]}, { "$set": { "passwordReset": {
        "_id": resetToken,
        "createdAt": datetime.utcnow()
    } } })

    send_email(
        subject='MineOnline - Reset Your Password',
        sender='mineonline@codie.gg',
        recipients=[user['email']],
        text_body="Password reset requested.\r\nVisit " + url + "?token=" + str(resetToken) + " to change your password."
    )
    
    return render_template("public/forgotpass.html", success="Instructions to reset your password have been sent to your email adress.\r\nMake sure to check the spam folder.")

@app.route('/changepass.jsp', methods = ["POST"])
def changepasspost():
    users = mongo.db.users
    token = None
    if 'token' in request.form:
        token = request.form['token']

    try:
        if token:
            try:
                print(token)
                user = users.find_one({"passwordReset._id": ObjectId(token)})
            except:
                return render_template("public/changepass.html", error="Invalid password reset.", token=token)
            if not user:
                return render_template("public/changepass.html", error="Invalid password reset.", token=token)
            if (datetime.utcnow() - user['passwordReset']['createdAt']).total_seconds() > 24 * 60 * 60:
                return render_template("public/changepass.html", error="Password reset expired. Please reset your password again.", token=token)
        elif 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(request.cookies['sessionId'])})
            if not user:
                return redirect('/login.jsp')
            
            matched = bcrypt.checkpw(request.form['currentPassword'].encode('utf-8'), user['password'].encode('utf-8'))
            if not matched:
                return render_template("public/changepass.html", error="Incorrect password.", token=token)
        else:
            return redirect('/login.jsp')

        if request.form['password1'] == "" or request.form['password2'] == "":
            return render_template("public/changepass.html", error="Please enter a password.", token=token)
        elif request.form['password1'] != request.form['password2']:
            return render_template("public/changepass.html", error="Passwords don't match.", token=token)

        sessionId = ObjectId()
        users.update_one({  "_id": user['_id'] }, { "$set": {
            "password": bcrypt.hashpw(request.form['password1'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            "passwordReset": {},
            "sessionId": sessionId
        }})

        return render_template("public/login.html", sessionId=str(sessionId))

    except:
        return render_template("public/changepass.html", error="An error occured while resetting your password.", token=request.form['token'])


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
                "createdAt": datetime.utcnow(),
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
            return redirect('/login.jsp')
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

# unknown endpoint, found in infdev, may be in more.
@app.route('/game/')
def unknown1():
    name = request.args.get('n')
    i = request.args.get('i')
    return Response("1")

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
    server = request.args.get('server')
    serverIP = None
    serverPort = None
    mppass = None

    if 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
        try:
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(request.cookies['sessionId'])})
            if not user:
                sessionIdInvalid = True
        except:
            pass

    server = mongo.db.classicservers.find_one({"_id": ObjectId(server)})
    if server:
        serverIP = server['ip']
        serverPort = server['port']
        if user:
            mppass = str(hashlib.md5((server['salt'] + user['user']).encode('utf-8')).hexdigest())

    return render_template("public/play.html", 
        user=user,
        serverIP=serverIP, 
        serverPort=serverPort,
        mppass=mppass,
        sessionIdInvalid=sessionIdInvalid
    )

@app.route('/servers.jsp')
def classicservers():
    user = None
    sessionIdInvalid = False

    if 'sessionId' in request.cookies and request.cookies['sessionId'] != "":
        try:
            users = mongo.db.users
            user = users.find_one({"sessionId": ObjectId(request.cookies['sessionId'])})
            if not user:
                sessionIdInvalid = True
        except:
            pass

    servers = list(mongo.db.classicservers.find())

    serverCount = mongo.db.classicservers.count_documents({})
    usersCount = 0
    privateCount = 0
    for server in servers:
        usersCount = usersCount + int(server['users'])
        if server['public'] == "false":
            privateCount = privateCount + 1
        
    timeString = datetime.utcnow().strftime("%H:%M") + " (UTC) " + datetime.utcnow().strftime("%B %d")


    return render_template("public/servers.html", 
        user=user,
        servers=servers,
        sessionIdInvalid=sessionIdInvalid,
        serverCount=serverCount,
        usersCount=usersCount,
        privateCount=privateCount,
        timeString=timeString,
    )


#classic
@app.route('/listmaps.jsp')
def listmaps():
    username = request.args['user']
    maps = None

    try:
        users = mongo.db.users
        user = users.find_one({"user" : username})
    except:
        return Response("User not found.", 404)

    if (user == None):
        return Response("User not found.", 404)

    if 'maps' in user:
        maps = user['maps']
    else:
        return Response("-;-;-;-;-")

    return Response(';'.join([
        maps['0']['name'] if '0' in maps else '-',
        maps['1']['name'] if '1' in maps else '-',
        maps['2']['name'] if '2' in maps else '-',
        maps['3']['name'] if '3' in maps else '-',
        maps['4']['name'] if '4' in maps else '-',
    ]))

#classic
#TODO: GZIP V1 maps.
@app.route('/level/save.html', methods=['POST'])
def savemap():
    username = None
    sessionId = None
    mapId = None
    mapLength = None
    mapName = None

    nullcount = 0
    lastNull = 0

    user = None

    try:
        requestData = request.stream.read()

        username_length = int.from_bytes(requestData[1 : 2], byteorder='big')
        username = requestData[2 : 2 + username_length]
        sessionId_length = int.from_bytes(requestData[2 + username_length + 1 : 2 + username_length + 2], byteorder='big')
        sessionId = requestData[2 + username_length + 2 : 2 + username_length + 2 + sessionId_length]
        mapName_length = int.from_bytes(requestData[2 + username_length + 2 + sessionId_length + 1 : 2 + username_length + 2 + sessionId_length + 2], byteorder='big')
        mapName = requestData[2 + username_length + 2 + sessionId_length + 2 : 2 + username_length + 2 + sessionId_length + 2 + mapName_length]
        mapId = requestData[2 + username_length + 2 + sessionId_length + 2 + mapName_length]
        mapLength = int.from_bytes(requestData[2 + username_length + 2 + sessionId_length + 2 + mapName_length + 1 : 2 + username_length + 2 + sessionId_length + 2 + mapName_length + 1 + 4], byteorder='big')
        mapData = requestData[2 + username_length + 2 + sessionId_length + 2 + mapName_length + 1 + 4 : len(requestData)]

        username = str(utf8m_to_utf8s(username), 'utf-8')
        sessionId = str(utf8m_to_utf8s(sessionId), 'utf-8')
        mapName = str(utf8m_to_utf8s(mapName), 'utf-8')

    except:
        return Response("Something went wrong!", 500)

    try:
        users = mongo.db.users
        user = users.find_one({"user" : username, "sessionId": ObjectId(sessionId)})
    except:
        return Response("Invalid Session", 401)

    if (user == None):
        return Response("Invalid Session", 401)

    try:
        users.update_one({"_id": user["_id"]}, { "$set": { ("maps." + str(mapId)): {
            "name": mapName,
            "length": mapLength,
            "data": mapData,
            "createdAt": datetime.utcnow(),
        } } })
    except:
        return Response("Failed to save data.", 500)

    return Response("ok")

#classic
@app.route('/level/load.html')
def loadmap():
    username = request.args['user']
    mapId = request.args['id']
    maps = None

    try:
        users = mongo.db.users
        user = users.find_one({"user" : username})
    except:
        return Response("User not found.", 404)

    if (user == None):
        return Response("User not found.", 404)

    if 'maps' in user:
        maps = user['maps']
    else:
        return Response("Map not found.", 404)

    if mapId in maps:
        response = Response(bytes([0x00, 0x02, 0x6F, 0x6B]) + maps[mapId]['data'], mimetype='application/x-mine')
        return response

#classic
@app.route('/heartbeat.jsp', methods=["POST"])
def addclassicserver(): 
    port = request.values['port']
    users = request.values['users']
    maxUsers = request.values['max']
    name = request.values['name']
    public = request.values['public']
    version = request.values['version']
    salt = request.values['salt']
    if 'ip' in request.values:
        ip = request.values['ip'] # new to mineonline to allow classic servers on different IPs
    else:
        ip = request.remote_addr

    classicservers = mongo.db.classicservers

    user = None

    if(port == None):
        port = "25565"

    try:
        # Delete existing server record
        classicservers.delete_many({"port": port, "ip": ip})

        _id = ObjectId()

        currentlisting = classicservers.find_one({"port": port, "ip": ip})
        if currentlisting:
            _id = currentlisting['_id']

        classicservers.insert_one({
            "_id": _id,
            "createdAt": datetime.utcnow(),
            "ip": ip,
            "port": port,
            "users": users,
            "maxUsers": maxUsers,
            "name": name,
            "public": public,
            "version": version,
            "salt": salt,
        })
        
        if (port != "25565"):
            return Response("http://www.minecraft.net/play.jsp?server=" + str(_id.inserted_id) + "&port=" + port)
        else:
            return Response("http://www.minecraft.net/play.jsp?server=" + str(_id.inserted_id))

    except:
        return Response("Something went wrong.", 500)

    return Response("Something went wrong.", 500)

#not sure when this was used, but it definately existed!
@app.route('/haspaid.jsp')
def haspaid():
    username = request.args.get('user')

    try:
        users = mongo.db.users
        user = users.find_one({"user" : username})
    except:
        return Response("false")
    
    if not user or not user['premium']:
        return Response("false")

    return Response("true")

#classic, mineonline
@app.route('/mineonline/mppass.jsp')
def getmmpass():
    sessionId = request.args['sessionId']
    serverIP = request.args['serverIP']
    serverPort = request.args['serverPort']

    try:
        users = mongo.db.users
        user = users.find_one({"sessionId": ObjectId(sessionId)})
    except:
        return Response("User not found.", 404)

    if (user == None):
        return Response("User not found.", 404)

    try:
        server = mongo.db.classicservers.find_one({"ip": serverIP, "port": serverPort})
    except:
        return Response("Server not found.", 404)

    if server:
        mppass = str(hashlib.md5((server['salt'] + user['user']).encode('utf-8')).hexdigest())
        return Response(mppass)
    else:
        return Response("Server not found.", 404)

    return Response("Something went wrong!", 500)

#classic, mineonline
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

#mineonline
@app.route('/mineonline/skin.jsp', methods=['POST'])
def saveskin():
    username = None
    sessionId = None

    user = None

    try:
        requestData = request.stream.read()

        username_length = int.from_bytes(requestData[1 : 2], byteorder='big')
        username = requestData[2 : 2 + username_length]
        sessionId_length = int.from_bytes(requestData[2 + username_length + 1 : 2 + username_length + 2], byteorder='big')
        sessionId = requestData[2 + username_length + 2 : 2 + username_length + 2 + sessionId_length]
        skinLength = int.from_bytes(requestData[2 + username_length + 2 + sessionId_length + 2: 2 + username_length + 2 + sessionId_length + 2 + 4], byteorder='big')
        skinData = requestData[2 + username_length + 2 + sessionId_length + 4 : len(requestData)]

        username = str(utf8m_to_utf8s(username), 'utf-8')
        sessionId = str(utf8m_to_utf8s(sessionId), 'utf-8')

    except:
        return Response("Something went wrong!", 500)

    try:
        users = mongo.db.users
        user = users.find_one({"user" : username, "sessionId": ObjectId(sessionId)})
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
        skin = skin.crop((0, 0, 64, 32))
        skin.save(croppedSkin, "PNG")
        skinBytes.flush()
        croppedSkin.seek(0)
        users.update_one({ "_id": user["_id"] }, { "$set": { "skin": croppedSkin.read() } })
    except:
        return Response("Failed to upload skin.", 500)

    return Response("ok")

#mineonline
@app.route('/mineonline/cloak.jsp', methods=['POST'])
def savecloak():
    username = None
    sessionId = None

    user = None

    try:
        requestData = request.stream.read()

        username_length = int.from_bytes(requestData[1 : 2], byteorder='big')
        username = requestData[2 : 2 + username_length]
        sessionId_length = int.from_bytes(requestData[2 + username_length + 1 : 2 + username_length + 2], byteorder='big')
        sessionId = requestData[2 + username_length + 2 : 2 + username_length + 2 + sessionId_length]
        cloakLength = int.from_bytes(requestData[2 + username_length + 2 + sessionId_length + 2: 2 + username_length + 2 + sessionId_length + 2 + 4], byteorder='big')
        cloakData = requestData[2 + username_length + 2 + sessionId_length + 4 : len(requestData)]

        username = str(utf8m_to_utf8s(username), 'utf-8')
        sessionId = str(utf8m_to_utf8s(sessionId), 'utf-8')

    except:
        return Response("Something went wrong!", 500)

    try:
        users = mongo.db.users
        user = users.find_one({"user" : username, "sessionId": ObjectId(sessionId)})
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

@app.route('/', defaults={'path': 'index'})
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
            return render_template("private/" + path + ".html", user=user)
        else:
            return redirect('/login.jsp')
    elif os.path.exists("templates/public/" + path + ".html"):
        return render_template("public/" + path + ".html", user=user, latestVersion=latestVersion, readme_html=readme_html, args=request.args)
    elif os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)

    return abort(404)




def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except ConnectionRefusedError:
            raise EnvironmentError("[MAIL SERVER] not working")


def send_email(subject, sender, recipients, text_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    Thread(target=send_async_email, args=(app, msg)).start() 




if __name__ == '__main__':
    app.secret_key = secretkey
    app.run(host= '0.0.0.0', port=port, debug=True)
