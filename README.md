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
- None known.
  
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
```

## TODO:
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
