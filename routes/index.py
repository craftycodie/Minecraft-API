from routes.legacy import register_routes as register_legacy_routes
from routes.mineonline import register_routes as register_mineonline_routes
from routes.realms import register_routes as register_realms_routes


def register_routes(app, mongo):
    register_legacy_routes(app, mongo)
    register_mineonline_routes(app, mongo)
    register_realms_routes(app, mongo)