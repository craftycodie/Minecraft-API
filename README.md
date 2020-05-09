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
