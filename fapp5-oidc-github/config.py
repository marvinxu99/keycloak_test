import os

class Config:
    SECRET_KEY = os.urandom(24)

    # Keycloak config
    KEYCLOAK_BASE_URL = "http://localhost:8080"
    REALM_NAME = "MyRealm"
    CLIENT_ID = "fapp1"
    CLIENT_SECRET = "9v35FAZMzQt5coPomh2CBgvRkJrYd4CJ"

    # Admin API config
    ADMIN_USER = "admin"
    ADMIN_PASS = "admin"
    ADMIN_CLIENT_ID = "admin-cli"

    KEYCLOAK_USERS_URL = f"{KEYCLOAK_BASE_URL}/admin/realms/{REALM_NAME}/users"