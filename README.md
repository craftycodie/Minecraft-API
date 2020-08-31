# Minecraft API Recreation
This project aims to provide a server capable of running any pre-release version of Minecraft, fully featured.

## Restored and Recreated Features
These are features which are no longer available through official servers.

- Launcher Authentication and Updates (not including new launcher)

- Server Authentication

- Skins and Cloaks

- Server List

- Online World Saves

- Realms
  
## How To Use
To host the site, create a config.py file based on the provided config_example.py and run server.py.
To use the website with a game you will have to point requests to minecraft.net and s3.amazonaws.com to your local machine, or wherever you're hosting this.
The easiest way to connect your game is to use [MineOnline](https://github.com/codieradical/MineOnline), but you can also use a proxy, the hosts file, modify game bytecode or just recompile the game entirely.
You will also need to provide game files inside the public folder (ie minecraft.jar goes in public/MinecraftDownload/) if you wish to use old updaters.

## Serving Assets
The API is written to serve files that used to be (and sometimes still are) hosted on AWS.
The recommended file tree is as follows:

public/
```
│   minecraft-server.zip                  classic server files
│
├───download
│   │   Minecraft.exe                     launcher exe (windows)
│   │   Minecraft.jar                     launcher jar (linux / any)
│   │   Minecraft.zip                     launcher app (zip, mac)
│   │   Minecraft_Server.jar              server jar
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
│   │   version                           Contains a version timestamp. Numbers work too.
│   │
│   ├───classic                           Classic version applet (browser) files.
│   │   │   jinput.jar.pack.lzma
│   │   │   linux_natives.jar.lzma
│   │   │   logo_small.png
│   │   │   lwjgl.jar.pack.lzma
│   │   │   lwjgl_applet.jar.pack.lzma
│   │   │   lwjgl_util.jar.pack.lzma
│   │   │   lwjgl_util_applet.jar
│   │   │   lzma.jar
│   │   │   macosx_natives.jar.lzma
│   │   │   minecraft.jar
│   │   │   solaris_natives.jar.lzma
│   │   │   windows_natives.jar.lzma
│   │
│   └───launcher
│       │   MinecraftLauncher.jar         Used for the in browser game.
│
├───MinecraftResources                    from http://s3.amazonaws.com/MinecraftResources/
│   │   download.xml                      This is the index document tree from that url ^
├───resources                             Sound files for older minecraft versions.
│   │   index.txt                         A list of each sound file. Has extra data.
|
├───mc
│   │───assets                            Assets for release minecraft versions.
│   └───game
|       |   version_manifest.json         An index of versions for the modern launcher.
│
├───<package>                             Libraries for release minecraft versions.
│   └───<name>
│       └───<version>
|           │   <name>-<version>.jar
|           │   <name>-<version>.jar.sha1
|
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

## The Database

The Mongo Database contains three Collections.

- Serverjoins

These are created for server authentication when a logged in player attempts to join a server.
If the server is in online-mode, it will only allow joins if a serverjoin exists, then the serverjoin is deleted.

- Classicservers

These are classic servers displayed on the server list.
Documents are created on server heartbeat, and expire after about a minute and a half unless another heartbeat request is received.
These are used to get server information such as salt, ip and port from the server ID, which makes it necessary for classic server authentication.

- Users

```
{
    "_id": {
        "$oid": "[redacted]"
    },
    "user": "codie",
    "uuid": "ddb16e30-646a-45aa-9939-68e1ee10e906"
    "email": "[redacted]",
    "password": "[redacted]",
    "premium": true,
    "slim": true,
    "sessionId": {
        "$oid": "[redacted]"
    },
    "createdAt": {
        "$date": "2020-05-16T13:14:33.790Z"
    },
    "maps": {
        "0": {
            "name": "Classic Test World",
            "length": 198865,
            "data": "<Binary Data>"
        },
        "4": {
            "name": "test2",
            "length": 222887,
            "data": "<Binary Data>"
        },
        "1": {
            "name": "Website Save!",
            "length": 198880,
            "data": "<Binary Data>"
        },
        "2": {
            "name": "Water",
            "length": 26560,
            "data": "<Binary Data>"
        },
        "3": {
            "name": "InDev Test World",
            "length": 130575,
            "data": "<Binary Data>"
        }
    },
    "passwordReset": {
        "_id": {
            "$oid": "[redacted]"
        },
        "createdAt": {
            "$date": "2020-05-16T10:11:09.170Z"
        }
    },
    "skin": "<Binary Data>",
    "cloak": "<Binary Data>"
}
```
