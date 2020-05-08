from config import port
from flask import Flask, Response, request, send_from_directory, abort, send_file, render_template
import json
import os


app = Flask(__name__,
            static_folder='public/',
            template_folder='templates')


latestVersion = "0.0.3"

@app.route('/game/getversion', methods = ["POST"])
def getversion():
    username = request.form['user']
    password = request.form['password']

    downloadToken = "download"
    sessionId = "sessionId"
    response = Response(':'.join([latestVersion, downloadToken, username, sessionId]))
    return response

@app.route('/game/joinserver')
def joinserver():
    username = request.args.get('user')
    sessionId = request.args.get('sessionId')
    serverId = request.args.get('serverId')

    response = Response("ok")
    return response

@app.route('/game/checkserver')
def checkserver():
    username = request.args.get('user')
    serverId = request.args.get('serverId')

    response = Response("YES")
    return response



@app.route('/MinecraftSkins/<username>.png')
def skin(username):
    if path != "" and os.path.exists("public/MinecraftSkins" + username + ".png"):
        return send_file("public/MinecraftSkins" + username + ".png", mimetype="image/png")
    else:
        return abort(404)



@app.route('/MinecraftDownload/minecraft.jar')
def downloadgame():
    username = request.args.get('user')
    downloadTicket = request.args.get('ticket')

    return send_file("public/MinecraftDownload/minecraft.jar")

@app.route('/')
def index():
    return serve("index");


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists("templates/" + path + ".html"):
        # session = { "user": "codieradical", "downloadticket": "yeet", "id": "yeet" }
        session = None
        return render_template(path + ".html", session=session, latestVersion=latestVersion)
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return abort(404)





# If the file is being run, call the main function.
if __name__ == '__main__':
  app.run(port=port)