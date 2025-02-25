from flask import Flask, redirect, request, session, jsonify
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 🔹 Update this section with correct Keycloak URLs
KEYCLOAK_BASE_URL = "http://localhost:8080"  # Adjust if using Docker (See Step 4)
REALM_NAME = "MyRealm"

CLIENT_ID = "fapp1"
CLIENT_SECRET = "RnRJ1IF6NI6ALUB8YIt4YRwltzr8kG97"  # Replace with actual secret

oauth = OAuth(app)
keycloak = oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    # authorize_url=f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/protocol/openid-connect/auth",
    # token_url=f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/protocol/openid-connect/token",
    # userinfo_url=f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/protocol/openid-connect/userinfo",
    server_metadata_url=f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)

@app.route("/")
def home():
    return 'Welcome to fapp1! <a href="/login">Login with Keycloak</a>'

@app.route("/login")
def login():
    redirect_uri = "http://localhost:5001/callback"  # Ensure this matches Keycloak settings
    return keycloak.authorize_redirect(redirect_uri=redirect_uri)

@app.route("/callback")
def callback():
    # token = keycloak.authorize_access_token()
    # if not token:
    #     return "Failed to retrieve token", 400
    # session["token"] = token
    # user_info = keycloak.get("userinfo").json()
    # return jsonify(user_info)

    print("Received callback request:", request.args)  # Debugging

    if 'code' not in request.args:
        return "Error: Authorization code not received!", 400

    try:
        token = keycloak.authorize_access_token()
        print(f"Access Token: {token}")  # Debugging
    except Exception as e:
        print(f"Error retrieving token: {e}")  # Debugging
        return f"Error retrieving token: {e}", 500

    session["token"] = token
    
    # Fetch userinfo explicitly using the access token
    try:
        headers = {"Authorization": f"Bearer {token['access_token']}"}
        userinfo_url = f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/protocol/openid-connect/userinfo"
        response = oauth.keycloak.get(userinfo_url, headers=headers)
        
        if response.status_code != 200:
            print(f"Error fetching userinfo: {response.status_code}, {response.text}")  # Debugging
            return f"Error fetching userinfo: {response.status_code}, {response.text}", 500
        
        user_info = response.json()
        return jsonify(user_info)

    except Exception as e:
        print(f"Error retrieving user info: {e}")  # Debugging
        return f"Error retrieving user info: {e}", 500
    

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(port=5001, debug=True)
