from config import port
from flask import Flask, Response, request, send_from_directory, abort, send_file
import json
import os


app = Flask(__name__,
            static_folder='public/',)


@app.route('/game/getversion', methods = ["POST"])
def getversion():
    username = request.form['user']
    password = request.form['password']

    version = "0.0.2"
    downloadToken = "download"
    sessionId = "sessionId"
    response = Response(':'.join([version, downloadToken, username, sessionId]))
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

    return send_file("src/testskin.png", mimetype="image/png")

@app.route('/MinecraftDownload/minecraft.jar')
def downloadgame():
    username = request.args.get('user')
    downloadTicket = request.args.get('ticket')

    return send_file("public/MinecraftDownload/minecraft.jar")

@app.route('/')
def index():
    return send_file("src\index.html")

@app.route('/download')
def download():
    return send_file("src\download.html")




@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return abort(404)





# If the file is being run, call the main function.
if __name__ == '__main__':
  app.run(port=port)