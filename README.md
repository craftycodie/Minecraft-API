# Minecraft API Recreation
This project aims to provide a server capable of running any pre-release version of Minecraft, fully featured.

## NEW - MineOnline
[MineOnline](https://github.com/codieradical/MineOnline) is a launcher which uses this API to run any pre-release version of minecraft.

## Restored Features
These are features which are no longer available through official servers.
- Launcher Authentication and Updates
- Server Authentication
- Skins
- Classic Server List
- Online World Saves

## API - Differences
- When running the development server, V1 map files are too large to save, causing a hang.
  
## How To Use
If you wish to use this API, I recommend that you do so with older versions of Minecraft, as it was tested with Beta 1.7.3 and the alpha launcher.
To host the site, create a config.py file based on the provided config_example.py and run server.py.

To use the website with a game you will have to point requests to minecraft.net and s3.amazonaws.com to your local machine, or wheever you're hosting this. You can use a proxy, the hosts file, modify game bytecode or just recompile the game entirely.
You will also need to provide game files inside the public folder (ie minecraft.jar goes in public/MinecraftDownload/) if you wish to use old updaters.

## Serving Assets
The API is written to serve files that used to be (and sometimes still are) hosted on AWS.
The recommended file tree is as follows:

public/
```
│   minecraft-server.zip                  classic server files
│
├───download
│       Minecraft.exe                     launcher exe (windows)
│       Minecraft.jar                     launcher jar (linux / any)
│       Minecraft.zip                     launcher app (zip, mac)
│       Minecraft_Server.jar              server jar
│
├───MinecraftDownload                     from http://s3.amazonaws.com/MinecraftDownload/
│   │   jinput.jar
│   │   jinput.jar.pack.lzma
│   │   linux_natives.jar
│   │   linux_natives.jar.lzma
│   │   lwjgl.jar
│   │   lwjgl.jar.pack.lzma
│   │   lwjgl_applet.jar
│   │   lwjgl_applet.jar.pack.lzma
│   │   lwjgl_util.jar
│   │   lwjgl_util.jar.pack.lzma
│   │   lwjgl_util_applet.jar
│   │   lzma.jar
│   │   macosx_natives.jar
│   │   macosx_natives.jar.lzma
│   │   minecraft.jar
│   │   solaris_natives.jar
│   │   solaris_natives.jar.lzma
│   │   windows_natives.jar
│   │   windows_natives.jar.lzma
│   │
│   ├───classic                           Classic version applet (browser) files.
│   │       jinput.jar.pack.lzma
│   │       linux_natives.jar.lzma
│   │       logo_small.png
│   │       lwjgl.jar.pack.lzma
│   │       lwjgl_applet.jar.pack.lzma
│   │       lwjgl_util.jar.pack.lzma
│   │       lwjgl_util_applet.jar
│   │       lzma.jar
│   │       macosx_natives.jar.lzma
│   │       minecraft.jar
│   │       solaris_natives.jar.lzma
│   │       windows_natives.jar.lzma
│   │
│   └───launcher
│           MinecraftLauncher.jar         Used for the in browser game.
│
├───MinecraftResources                    from http://s3.amazonaws.com/MinecraftResources/
│   │   download.xml                      This is the index document tree from that url ^
│
├───MinecraftSkins                        Skins for each user, ie /MinecraftSkins/Notch.png
```

## API Endpoints
Endpoints have been reimplemented based on what data the client/server/launchers send, where they send it, and what they expect in response. There may be undocumented responses.
```
• POST /game/getversion.jsp
  ○ Login & check for updates.
  ○ ?user=<username/email>&password=<password>&version=<unix timestamp>
  ○ 200 OK "<latestVersion unix timestamp>:<downloadToken>:<username>:<sessionId>
  ○ 200 OK "Bad login"
  ○ 200 OK "Old version"
  ○ 200 OK "User not premium."
• GET /game/joinserver.jsp
  ○ Request authentication to join a server.
  ○ ?user=<username>&sessionId=<session>&serverId=<serverId>
  ○ 200 OK "ok"
  ○ 200 OK <error message>
• GET /game/checkserver.jsp
  ○ Check if a player has permission to join the server.
  ○ ?user=<username>&serverId=<serverId>
  ○ 200 OK "YES"
  ○ 200 OK <error message>
• GET /login/session.jsp
  ○ Check if a player owns the game (/ is logged in elsewhere?).
  ○ ?name=<username>&session=<sessionId>
  ○ 200 OK
  ○ 400 Bad Request


Classic Endpoints
• GET /listmaps.jsp
  ○ List saved classic maps.
  ○ ?user=<username>
  ○ 200 OK <mapnames>
    - ; separated list of strings. '-' represents empty slots. 5 maps in total.
  ○ Any error code.
• POST /level/save.html
  ○ Save a classic map.
  ○ Post contains:
    1. username
    2. sessionId
    3. map name
    4. map id (0 - 4)
    5. map length
    6. map data
  ○ 200 OK "ok".
  ○ Any error code.
• GET /level/load.html
  ○ Check if a player has permission to join the server.
  ○ ?id=<0-4>&user=<username>
  ○ 200 OK "ok" and map data, classic v2 format (gzip/dat).
  ○ 200 OK <error message>
  ○ Any error code.
• POST /heartbeat.jsp
  ○ Classic server list.
  ○ ?port=<port>&users=<current user count>&max=<max user count>&name=<name>&public=<true/false>&version=<protocol version (7)>&salt=<A random, 16-character base-62 salt>
• GET /haspaid.jsp
  ○ Check if a player is premium.
  ○ ? user=<username>
  ○ 200 OK "true" or "false"

MineOnline Endpoints
• Used by https://github.com/codieradical/MineOnline
• GET /mineonline/getserver.jsp
  ○ Get a server IP and Port from it's ID.
  ○ ?server=<serverId>
  ○ 200 OK "<ip>:<port>"
  ○ 404 Not Found
• GET /mineonline/mppass.jsp
  ○ Get an auth token for a pre-alpha server.
  ○ ?sessionId=<sessionId>&serverIP=<serverIP>&serverPort=<serverPort>
  ○ 200 OK "<mppass>"
  ○ 404 Not Found

```

## Playing In Browser (Applet)
Currently the project has minimal support for playing older versions of Minecraft in browser.
The classic applet doesn't seem to work yet.
This process is currently quite complicated and may not work, expect better support for this in future.
If you are unsure of any of these steps, do not proceed.

1. Place all necessary files into the public/ folder.

You will need public/MinecraftDownload/MinecraftLauncher.jar and everything in public/MinecraftDownload for old game versions.
You can pull these from https://s3.amazonaws/MinecraftDownload/, or just find the relevant files in a current minecraft install.
See [Serving Assets](https://github.com/codieradical/Minecraft-API#serving-assets).
For classic, everything in public/MinecraftDownload/classic/ shouls suffice.
If you're playing on anything but windows you'll need to grab the latest natives, you can find these in an existing current version minecraft install or in an lwjgl 2.x release.

2. Self sign every jar.

To run the applet, you're probably going to need to sign every jar file.
There are plenty of guides on how to do this, [here's one](https://stackoverflow.com/questions/17187520/signing-jar-file).
Note: In testing I used a modified launcher which did not use natives jars, lmzas or packs, these probably do need signing too, but the lmza and pack files likely also need signing. If this causes any trouble, just manually install the game the old fashioned way (.minecraft/bin) making sure to use the signed jars.

3. Grab an old browser & configure Java.

Modern browsers don't support Java anymore so you'll need an old one. I used Chrome 41.
You may also need to add some exceptions, and the signature you used to sign, in the Java control panel.

4. Prepare the API.

You're not going to need a full database and auth just to play in browser, so you won't need to fill in any of that stuff in config.py.
So assuming you don't have a database setup, you'll need to do the following:
Go to server.py. In the serve function, before the line 
  
          `return render_template("public/" + path + ".html", user=user, latestVersion=latestVersion)`
        
add the line
     
          `user = {"user" : "<username>", "downloadTicket": "deprecated", "sessionId": "<anything>" }`

If you already have the game files installed, it is recommended to make a backup.
You'll also want to make a version file (that's the name, no extension) containing

```

<version timestamp (see server.py for this)>
```

Once you've done all of that, you should be good to go!
Good luck! Contact me on Discord if you get stuck! Codie#0642


## TODO:
- Implement Password Reset.
- Tidy pages.
