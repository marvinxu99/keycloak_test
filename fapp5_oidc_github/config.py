import os

class Config:
    SECRET_KEY = os.urandom(24)

    # Keycloak config
    KEYCLOAK_BASE_URL = "http://localhost:8080"
    REALM_NAME = "MyRealm_Github"
    CLIENT_ID = "vpp_portal_oidc"
    CLIENT_SECRET = "HAGWIZpztWNs7QS00sdugZHRWY9y1cRB"
    VALID_REDIRECT_URI = "http://localhost:5005/callback"

    # Admin API config
    ADMIN_USER = "admin"
    ADMIN_PASS = "admin"
    ADMIN_CLIENT_ID = "admin-cli"

    KEYCLOAK_USERS_URL = f"{KEYCLOAK_BASE_URL}/admin/realms/{REALM_NAME}/users"