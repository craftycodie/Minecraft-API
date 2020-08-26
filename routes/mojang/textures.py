from uuid import UUID
from flask import Response, abort
from io import BytesIO
from PIL import Image

def register_routes(app, mongo):
    @app.route('/skin/<uuid>/<md5>', methods=['GET'])
    def texturesskin(uuid, md5):
        uuid = str(UUID(uuid))
        try:
            user = mongo.db.users.find_one({ "uuid": uuid })
        except:
            return abort(404)

        if not user or not 'skin' in user or not user['skin']:
            return abort(404)


        skinBytes = BytesIO(user['skin'])
        skinBytes.flush()
        skinBytes.seek(0)
        skin = Image.open(skinBytes)

        [width, height] = skin.size

        # Convert 64x32 skins to 64x64
        if(height < 64):
            legacySkin = skin
            skin = Image.new("RGBA", (64, 64), (255, 255, 255, 0))
            skin.paste(legacySkin, (0, 0))
            leg = skin.crop((0, 16, 16, 32))
            arm = skin.crop((40, 16, 56, 32))
            skin.paste(leg, (16, 48))
            skin.paste(arm, (32, 48))
        else:
            skin = skin.crop((0, 0, 64, 64))

        croppedSkin = BytesIO()
        skin.save(croppedSkin, "PNG")
        skinBytes.flush()
        croppedSkin.seek(0)

        response = Response(croppedSkin.read(), mimetype="image/png")
        
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers['Cache-Control'] = 'public, max-age=0'

        return response

    @app.route('/cloak/<uuid>/<md5>', methods=['GET'])
    def texturescloak(uuid, md5):
        uuid = str(UUID(uuid))
        try:
            user = mongo.db.users.find_one({ "uuid": uuid })
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