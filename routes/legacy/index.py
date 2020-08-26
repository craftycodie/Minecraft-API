from routes.legacy.launcher import register_routes as register_launcher_routes
from routes.legacy.skins import register_routes as register_skins_routes
from routes.legacy.server_auth import register_routes as register_server_auth_routes
from routes.legacy.levels import register_routes as register_levels_routes

def register_routes(app, mongo):
    register_launcher_routes(app, mongo)
    register_skins_routes(app, mongo)
    register_server_auth_routes(app, mongo)
    register_levels_routes(app, mongo)