from flask import Blueprint, render_template, render_template_string

main_bp = Blueprint("main", __name__)

@main_bp.route("/")
@main_bp.route("/home")
def home():
    return render_template("home.html")

@main_bp.route("/about")
def about():
    return render_template_string("""
        <h2>About fapp5-oidc-github</h2>
        <p>This app demonstrates Flask + Keycloak integration with proxy management.</p>
        <a href="/">Back to Home</a>
    """)
