from flask import Blueprint, redirect, request, session, render_template_string, current_app as app
from auth import oauth, get_keycloak
import requests

auth_bp = Blueprint("auth", __name__, url_prefix="/")

@auth_bp.route("/login")
def login():
    redirect_uri = app.config['VALID_REDIRECT_URI']   #  "http://localhost:5005/callback"
    return get_keycloak().authorize_redirect(redirect_uri=redirect_uri)


@auth_bp.route("/callback")
def callback():
    if 'code' not in request.args:
        return "Error: Authorization code not received!", 400

    try:
        token = get_keycloak().authorize_access_token()
        session["token"] = token

        headers = {"Authorization": f"Bearer {token['access_token']}"}
        userinfo_url = f"{app.config['KEYCLOAK_BASE_URL']}/realms/{app.config['REALM_NAME']}/protocol/openid-connect/userinfo"
        response = oauth.keycloak.get(userinfo_url, headers=headers)

        if response.status_code != 200:
            return f"Error fetching userinfo: {response.status_code}, {response.text}", 500

        session["user_info"] = response.json()
        return redirect("/welcome")

    except Exception as e:
        return f"Error retrieving token or user info: {e}", 500


@auth_bp.route("/logout")
def logout():
    if "token" in session:
        id_token = session["token"].get("id_token", "")
        session.clear()
        logout_url = f"{app.config['KEYCLOAK_BASE_URL']}/realms/{app.config['REALM_NAME']}/protocol/openid-connect/logout"
        return redirect(f"{logout_url}?id_token_hint={id_token}&post_logout_redirect_uri=http://localhost:5005")

    return redirect("/")
