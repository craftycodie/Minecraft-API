# Minecraft 2011 API
A recreation of the Minecraft Beta 1.7.3 Backend.

The aim of this project is to recreate the Minecraft website and API as it appeared in 2011.
The site implements it's original endpoints as closely as possible.

## Restored Features
These are features which are no longer available through official servers.
- Launcher Authentication and Updates
- Basic Server Authentication
  - Beta 1.7.3 servers are all running in offline mode right now!
- Skins

## API - Differences
- Missing classic endpoints.
  
## How To Use
If you wish to use this API, I recommend that you do so with older versions of Minecraft, as it was tested with Beta 1.7.3 and the alpha launcher.
To host the site, create a config.py file based on the provided config_example.py and run server.py.

To use the website with a game you will have to decompile the launcher, client and server, and changed the endpoints from minecraft.net / AWS.
You will also need to provide game files inside the public folder (ie minecraft.jar goes in public/MinecraftDownload/).

## Serving Assets
The api is written to serve files that used to be (and sometimes still are) hosted on AWS.
The recommmended file tree is as follows:

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


Classic endpoints (not yet implemented).
• GET /listmaps.jsp
  ○ List saved classic maps.
  ○ ?user=<?>
  ○ 200 OK <unknwon response, ';' seperated.>
  ○ Any error code.
• POST /level/save.html
  ○ Save a classic map.
  ○ Post contains map data, unknown format.
  ○ 200 OK "ok"
  ○ 200 OK <error message>
  ○ Any error code.
• GET /level/load.html
  ○ Check if a player has permission to join the server.
  ○ ?id=<int>&user=<?>
  ○ 200 OK "ok" and unknown format save data.
  ○ 200 OK <error message>
  ○ Any error code.
• POST /heartbeat.jsp
  ○ Unknown, used by servers, maybe for the server list.
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
          
5. Redirect Requests (if necessary)

If you want the applet to install the game to .minecraft/bin (if it's not already there, and signed), youll need to route requests to minecraft.net and s3.amazonaws to this API. On windows you can use the hosts file for this, on other operating systems... you probably know how to do this if you're not on windows :P

If you already have the game files installed, it is recommended to make a backup.
You'll also want to make a version file (that's the name, no extension) containing

```

<version timestamp (see server.py for this)>
```

Once you've done all of that, you should be good to go!
Good luck! Contact me on Discord if you get stuck! Codie#0642


## TODO:
- "hybrid" mojang auth branch
- "applet" in browser game branch
- Buy pages could be closer to the original site.
  - Buying won't be implemented (obviously) but those pages currently assume the user is not logged in and or does not own minecraft.
  - Buying could be implemented without payment (ie press the buy button, the API now thinks you own minecraft).
- Profile page needs some style tweaks.
  - This page was fully remade by hand so it's a little off.
- Error messages could be closer to original.
  - I had nothing to compare to, should see if there are any videos of the old site with errors.
- Implement Password Reset.
- Move skins to the database.
  
## Credits
- All of the web client resources (HTML/CSS/JS etc) were pulled (and then modified) from the Wayback Machine.
