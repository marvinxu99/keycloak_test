from authlib.integrations.flask_client import OAuth

oauth = OAuth()
_keycloak = None  # internal name to prevent import cycles

def init_auth(app):
    global _keycloak
    oauth.init_app(app)
    _keycloak = oauth.register(
        name="keycloak",
        client_id=app.config["CLIENT_ID"],
        client_secret=app.config["CLIENT_SECRET"],
        server_metadata_url=f"{app.config['KEYCLOAK_BASE_URL']}/realms/{app.config['REALM_NAME']}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )

def get_keycloak():
    if _keycloak is None:
        raise RuntimeError("Keycloak OAuth client not initialized. Did you forget to call init_auth(app)?")
    return _keycloak
