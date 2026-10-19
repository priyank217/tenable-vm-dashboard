"""Flask route blueprints for the Tenable dashboard application."""

from routes.assets import bp as assets_bp
from routes.dashboard import bp as dashboard_bp
from routes.pages import bp as pages_bp
from routes.server_health import bp as server_health_bp
from routes.ssl import bp as ssl_bp
from routes.tags import bp as tags_bp


def register_blueprints(app):
    app.register_blueprint(pages_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(tags_bp)
    app.register_blueprint(ssl_bp)
    app.register_blueprint(server_health_bp)
