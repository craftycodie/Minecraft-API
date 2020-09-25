from flask import Response, request, make_response, abort, redirect, render_template
import json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import hashlib
from uuid import uuid4
import bcrypt
from utils.modified_utf8 import utf8m_to_utf8s, utf8s_to_utf8m
from datetime import datetime
from io import BytesIO, StringIO
from utils.email import send_email
import re
from routes import serve
from utils.servers import *
from PIL import Image
from utils.database import getclassicservers

ALLOWED_EXTENSIONS = ['png', 'mine', 'dat']
MAX_WORLD_SIZE = 10000000 # 10 MB

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.')[-1].lower() in ALLOWED_EXTENSIONS

''' Register legacy website routes. '''
def register_routes(app, mongo):
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

        # # check if the post request has the file part
        # if 'file' not in request.files:
        #     return render_template("private/profile.html", error="Something went wrong.", user=user)
        skinFile = request.files['file']
        cloakFile = request.files['cloak']

        # if skinFile.filename == '' and cloakFile.filename == '':
        #     return render_template("private/profile.html", error="No file selected.", user=user)

        if skinFile and allowed_file(skinFile.filename):
            if skinFile.stream.tell() > 8096:
                return render_template("private/profile.html", error="Skin too large.", user=user)
            skinBytes = BytesIO()
            skinFile.save(skinBytes)
            skinBytes.flush()
            skinBytes.seek(0)
            skin = Image.open(skinBytes)
            croppedSkin = BytesIO()

            [width, height] = skin.size

            if (width < 64 or height < 32):
                return render_template("private/profile.html", error="Skin too small.", user=user)
            elif (height < 64):
                skin = skin.crop((0, 0, 64, 32))
            elif (height >= 64 or width > 64):
                skin = skin.crop((0, 0, 64, 64))

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

        world1File = request.files['world1'] if "world1" in request.files else None
        world2File = request.files['world2'] if "world2" in request.files else None
        world3File = request.files['world3'] if "world3" in request.files else None
        world4File = request.files['world4'] if "world4" in request.files else None
        world5File = request.files['world5'] if "world5" in request.files else None

        if world1File != None or world2File != None or world3File != None or world4File != None or world5File != None:
            maps = dict()
            if "maps" in user:
                maps = user["maps"]

            if world1File != None and allowed_file(world1File.filename):
                if world1File.stream.tell() > MAX_WORLD_SIZE:
                    return render_template("private/profile.html", error="World 1 is too large.", user=user)

                world1Bytes = BytesIO()
                world1File.save(world1Bytes)
                world1Bytes.flush()
                world1Bytes.seek(0)
                world1Bytes = world1Bytes.read()
                maps["0"] = {
                    "name": world1File.filename[0:world1File.filename.rfind(".")],
                    "length": len(world1Bytes),
                    "data": world1Bytes,
                    "createdAt": datetime.utcnow(),
                    "version": 2 if world1Bytes[0:2] == bytes([0x1F, 0x8B]) else 1
                }
            
            if world2File != None and allowed_file(world2File.filename):
                if world2File.stream.tell() > MAX_WORLD_SIZE:
                    return render_template("private/profile.html", error="World 2 is too large.", user=user)

                world2Bytes = BytesIO()
                world2File.save(world2Bytes)
                world2Bytes.flush()
                world2Bytes.seek(0)
                world2Bytes = world2Bytes.read()
                maps["1"] = {
                    "name": world2File.filename[0:world2File.filename.rfind(".")],
                    "length": len(world2Bytes),
                    "data": world2Bytes,
                    "createdAt": datetime.utcnow(),
                    "version": 2 if world2Bytes[0:2] == bytes([0x1F, 0x8B]) else 1
                }
            
            if world3File != None and allowed_file(world3File.filename):
                if world3File.stream.tell() > MAX_WORLD_SIZE:
                    return render_template("private/profile.html", error="World 3 is too large.", user=user)

                world3Bytes = BytesIO()
                world3File.save(world3Bytes)
                world3Bytes.flush()
                world3Bytes.seek(0)
                world3Bytes = world3Bytes.read()
                maps["2"] = {
                    "name": world3File.filename[0:world3File.filename.rfind(".")],
                    "length": len(world3Bytes),
                    "data": world3Bytes,
                    "createdAt": datetime.utcnow(),
                    "version": 2 if world3Bytes[0:2] == bytes([0x1F, 0x8B]) else 1
                }
            
            if world4File != None and allowed_file(world4File.filename):
                if world4File.stream.tell() > MAX_WORLD_SIZE:
                    return render_template("private/profile.html", error="World 14 is too large.", user=user)

                world4Bytes = BytesIO()
                world4File.save(world4Bytes)
                world4Bytes.flush()
                world4Bytes.seek(0)
                world4Bytes = world4Bytes.read()
                maps["3"] = {
                    "name": world4File.filename[0:world4File.filename.rfind(".")],
                    "length": len(world4Bytes),
                    "data": world4Bytes,
                    "createdAt": datetime.utcnow(),
                    "version": 2 if world4Bytes[0:2] == bytes([0x1F, 0x8B]) else 1
                }
            
            if world5File != None and allowed_file(world5File.filename):
                if world5File.stream.tell() > MAX_WORLD_SIZE:
                    return render_template("private/profile.html", error="World 5 is too large.", user=user)

                world5Bytes = BytesIO()
                world5File.save(world5Bytes)
                world5Bytes.flush()
                world5Bytes.seek(0)
                world5Bytes = world5Bytes.read()
                maps["4"] = {
                    "name": world5File.filename[0:world5File.filename.rfind(".")],
                    "length": len(world5Bytes),
                    "data": world5Bytes,
                    "createdAt": datetime.utcnow(),
                    "version": 2 if world5Bytes[0:2] == bytes([0x1F, 0x8B]) else 1
                }
            
            users.update_one({ "_id": user["_id"] }, { "$set": { "maps": maps } })


        users.update_one({ "_id": user["_id"] }, { "$set": { "slim": True if request.form["slim"] == "true" else False } })
        user = users.find_one({"_id": user["_id"]})

        return render_template("private/profile.html", user=user)

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
            if len(request.form['password1']) > 64:
                return render_template("public/changepass.html", error="Password too long. Passwords can be up to 64 characters.", token=token)
            if len(request.form['password1']) < 6:
                return render_template("public/changepass.html", error="Password too short. Passwords must be at least 6 characters.", token=token)

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
        if len(request.form['password1']) > 64:
            return render_template("public/register.html", error="Password too long. Passwords can be up to 64 characters.")
        if len(request.form['password1']) < 6:
            return render_template("public/register.html", error="Password too short. Passwords must be at least 6 characters.")
        elif request.form['username'] == "":
            return render_template("public/register.html", error="Please enter a username.")
        if len(request.form['username']) > 16:
            return render_template("public/register.html", error="Username too long. Usernames can be up to 16 characters.")
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
                    "uuid": str(uuid4()),
                    "slim": False,
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

        mineOnlineServers = getclassicservers(mongo)
        featuredServers = list(mongo.db.featuredservers.find())
        featuredServers = [dict(server, **{'isMineOnline': False}) for server in featuredServers]
        servers = mineOnlineServers + featuredServers

        serverCount = mongo.db.classicservers.count_documents({}) + mongo.db.featuredservers.count_documents({})
        usersCount = 0
        privateCount = 0
        for server in servers:
            if 'users' in server:
                usersCount = usersCount + int(server['users'])
            if 'public' in server and  server['public'] == "false":
                privateCount = privateCount + 1
            
        timeString = datetime.utcnow().strftime("%H:%M") + " (UTC) " + datetime.utcnow().strftime("%B %d")

        def mapServer(x): 
            if(not"md5" in x):
                return
            if(not "whitelisted" in x):
                return

            if ("public" in x and x["public"] == False):
                return

            status = NONE

            if (x["onlinemode"] == False):
                status = OFFLINEMODE
            
            if (x["whitelisted"] == True and "whitelistUsers" in x and "whitelistIPs" in x):
                if (user != None):
                    if(user["user"] in x["whitelistUsers"] or request.remote_addr in x["whitelistIPs"]):
                        status = ON_THE_WHITELIST
                    else:
                        status = NOT_ON_THE_WHITELIST
                else:
                    status = WHITELISTED

            if (user != None and "bannedUsers" in x and "bannedIPs" in x and (user["user"] in x["bannedUsers"] or request.remote_addr in x["bannedIPs"])):
                status = BANNED

            playerUUIDs = []
            users = mongo.db.users
            if "players" in x:
                for player in x["players"]:
                    try:
                        playerData = users.find_one({"user": player})
                        playerUUIDs.append(playerData["uuid"].replace("-", ""))
                    except:
                        playerUUIDs.append(None)

            return { 
                "createdAt": str(x["createdAt"]) if "createdAt" in x else None,
                "ip": x["ip"] if status != BANNED and status != NOT_ON_THE_WHITELIST else None,
                "port": x["port"] if status != BANNED and status != NOT_ON_THE_WHITELIST else None,
                "users": x["users"] if "users" in x else "0",
                "maxUsers": x["maxUsers"] if "maxUsers" in x else "24",
                "name": x["name"],
                "onlinemode": x["onlinemode"],
                "md5": x["md5"],
                "isMineOnline": x["isMineOnline"] if "isMineOnline" in x else True,
                "status": status,
                "versionName": x["versionName"] if "versionName" in x else None,
                "players": x["players"] if "players" in x else [],
                "playerUUIDs": playerUUIDs
            }

        servers = list(map(mapServer, servers))
        servers = list(filter(filterServer, servers))


        return render_template("public/servers.html", 
            user=user,
            servers=servers,
            sessionIdInvalid=sessionIdInvalid,
            serverCount=serverCount,
            usersCount=usersCount,
            privateCount=privateCount,
            timeString=timeString,
        )