"""
Tenable dashboard application entrypoint.

Layering:
  app.py          → create Flask app, init DB, register routes
  config.py       → environment / sync settings
  services/       → Tenable client, export/sync, SQLite, caches
  utils/          → parsers, normalizers, Lumin/SSL metrics
  routes/         → HTTP pages + JSON APIs
  templates/ + static/ → UI shells and client JS
"""

from pathlib import Path

from flask import Flask

from config import PORT
from routes import register_blueprints
from services.server_health_db import ensure_server_health_schema
from services.ssl_cert_db import ensure_ssl_cert_schema
from services.vuln_db import init_db

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__, static_folder=str(BASE_DIR / "static"), static_url_path="/static")
app.config["TEMPLATES_AUTO_RELOAD"] = True

init_db()
ensure_ssl_cert_schema()
ensure_server_health_schema()
register_blueprints(app)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
