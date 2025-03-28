import requests
from flask import session, current_app as app
from auth.utils import get_admin_token

def get_keycloak_user_id():
    """Fetch the Keycloak user ID based on current session's username."""
    username = session.get("user_info", {}).get("preferred_username")
    if not username:
        raise Exception("No user logged in.")

    token = get_admin_token()
    if not token:
        raise Exception("Failed to get admin token.")

    headers = {"Authorization": f"Bearer {token}"}
    url = f"{app.config['KEYCLOAK_USERS_URL']}?username={username}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200 and response.json():
        return response.json()[0]["id"]
    raise Exception(f"Unable to find Keycloak user ID for {username}")


def get_user_details(user_id):
    """Fetch full user JSON from Keycloak using their ID."""
    token = get_admin_token()
    if not token:
        raise Exception("Failed to get admin token.")

    headers = {"Authorization": f"Bearer {token}"}
    url = f"{app.config['KEYCLOAK_USERS_URL']}/{user_id}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    raise Exception(f"Failed to retrieve user details: {response.text}")


def update_user_attributes(user_id, new_attributes):
    """Update user attributes (like Proxies) for the specified user."""
    token = get_admin_token()
    if not token:
        raise Exception("Failed to get admin token.")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # First, fetch the existing user JSON
    user_data = get_user_details(user_id)

    attributes = user_data.get("attributes", {})
    attributes.update(new_attributes)
    user_data["attributes"] = attributes

    url = f"{app.config['KEYCLOAK_USERS_URL']}/{user_id}"
    response = requests.put(url, json=user_data, headers=headers)

    if response.status_code not in [200, 204]:
        raise Exception(f"Failed to update user: {response.text}")
