import requests
from flask import current_app as app

def get_admin_token():
    data = {
        "client_id": app.config["ADMIN_CLIENT_ID"],
        "username": app.config["ADMIN_USER"],
        "password": app.config["ADMIN_PASS"],
        "grant_type": "password"
    }

    url = f"{app.config['KEYCLOAK_BASE_URL']}/realms/master/protocol/openid-connect/token"
    response = requests.post(url, data=data)

    if response.status_code == 200:
        return response.json()["access_token"]
    return None
