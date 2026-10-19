"""HTML page routes and legacy .html redirects."""

from flask import Blueprint, redirect, render_template

bp = Blueprint("pages", __name__)


@bp.route("/")
@bp.route("/dashboard")
def dashboard_page():
    return render_template("dashboard_lumin.html", active_nav="dashboard")


@bp.route("/dashboard-lumin")
def dashboard_lumin_redirect():
    return redirect("/", code=302)


@bp.route("/inventory")
def inventory_page():
    return render_template("index.html", active_nav="inventory")


@bp.route("/tags")
def tags_page():
    return render_template("tags.html", active_nav="tags")


@bp.route("/ports")
def ports_page():
    return render_template("ports.html", active_nav="ports")


@bp.route("/ssl-certificates")
def ssl_certificates_page():
    return render_template("ssl_certificates.html", active_nav="ssl")


@bp.route("/server-health")
def server_health_page():
    return render_template("server_health.html", active_nav="server_health")


@bp.route("/dashboard.html")
def dashboard_html_redirect():
    return redirect("/", code=302)


@bp.route("/index.html")
def index_html_redirect():
    return redirect("/inventory", code=302)


@bp.route("/tags.html")
def tags_html_redirect():
    return redirect("/tags", code=302)


@bp.route("/ports.html")
def ports_html_redirect():
    return redirect("/ports", code=302)


@bp.route("/ssl-certificates.html")
def ssl_certificates_html_redirect():
    return redirect("/ssl-certificates", code=302)


@bp.route("/server-health.html")
def server_health_html_redirect():
    return redirect("/server-health", code=302)
