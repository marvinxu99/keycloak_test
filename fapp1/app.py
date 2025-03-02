from flask import Flask, redirect, request, session, jsonify, render_template_string
from authlib.integrations.flask_client import OAuth
import os
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 🔹 Update this section with correct Keycloak URLs
KEYCLOAK_BASE_URL = "http://localhost:8080"  # Adjust if using Docker (See Step 4)
REALM_NAME = "MyRealm"

CLIENT_ID = "fapp1"
CLIENT_SECRET = "9v35FAZMzQt5coPomh2CBgvRkJrYd4CJ"  # Replace with actual secret

# For Keycloak Admin APIs
KEYCLOAK_ADMIN_USER = "admin"
KEYCLOAK_ADMIN_PASSWORD = "admin"
KEYCLOAK_CLIENT_ID = "admin-cli"  # For admin access
KEYCLOAK_CLIENT_SECRET = ""  # Not needed for admin-cli
KEYCLOAK_TOKEN_URL = f"{KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token"
KEYCLOAK_USERS_URL = f"{KEYCLOAK_BASE_URL}/admin/realms/{REALM_NAME}/users"


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
    return """<p>Welcome to fapp1! </p>
        </p>
        <div><a href="/login">Login with Keycloak</a></div>
        </p>
        <div><a href="/addnew">Redirect to KeyCloak to register a new user</a></div>
        </p>
        <div><a href="/register">Call Keycloak API to register a new user</a></div>
        </p>
        <div><a href="/logout">Logout</a></div>

        """

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
        # return jsonify(user_info

        # Extract user details for display
        # username = user_info.get("preferred_username", "Unknown")
        # email = user_info.get("email", "No email provided")
        # full_name = user_info.get("name", "No name available")

        session["user_info"] = user_info  # Store user info in session

        return redirect("/welcome")

    except Exception as e:
        print(f"Error retrieving user info: {e}")  # Debugging
        return f"Error retrieving user info: {e}", 500
    

@app.route("/welcome")
def welcome():
    if "user_info" not in session:
        return redirect("/")

    user_info = session["user_info"]
    username = user_info.get("preferred_username", "Unknown")
    email = user_info.get("email", "No email provided")
    full_name = user_info.get("name", "No name available")

    return f"""
        <p>Welcome, {full_name} - ({username})!</p>
        <p>Email: {email}</p>
        <div><a href="/logout">Logout</a></div>
    """


@app.route("/logout")
def logout():
    if "token" in session:
        id_token = session["token"].get("id_token", "")
        session.clear()  # Clear local session

        logout_url = f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/protocol/openid-connect/logout"
        params = {
            "id_token_hint": id_token,  # Helps Keycloak identify the session
            "post_logout_redirect_uri": "http://localhost:5001"  # Redirect back to fapp1
        }
        return redirect(f"{logout_url}?id_token_hint={id_token}&post_logout_redirect_uri={params['post_logout_redirect_uri']}")

    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register_user():
    '''
        Displays a form for user input and registers a new user in Keycloak.
        Call Keycloak Admin API to register a new user.
    '''

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")

        token = get_admin_token()
        if not token:
            return "Error: Could not authenticate with Keycloak", 500

        # 🔹 Construct user data
        new_user = {
            "username": username,
            "email": email,
            "enabled": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}],
            "firstName": first_name,
            "lastName": last_name,
        }

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        response = requests.post(KEYCLOAK_USERS_URL, json=new_user, headers=headers)

        if response.status_code in [200, 201]:  # Keycloak returns 201 for success
            return f"<h3>User {username} successfully registered!</h3><a href='/'>Back to Home</a>"
        else:
            return f"<h3>Error registering user: {response.text}</h3>", response.status_code

    # HTML form for user input
    return render_template_string("""
        <h2>Register a New User</h2>
        <form method="POST">
            <label>Username:</label>
            <input type="text" name="username" required><br><br>

            <label>Email:</label>
            <input type="email" name="email" required><br><br>

            <label>Password:</label>
            <input type="password" name="password" required><br><br>

            <label>First Name:</label>
            <input type="text" name="first_name" required><br><br>

            <label>Last Name:</label>
            <input type="text" name="last_name" required><br><br>

            <button type="submit">Register</button>
        </form>
        <br>
        <a href="/">Back to Home</a>
    """)
    

@app.route("/addnew")
def add_user():
    '''Redirect to KeyCloak a new user'''
    # return "Redirect to Keycloak a new user."
    return redirect(f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/protocol/openid-connect/registrations?client_id=account&response_type=code")


def get_admin_token():
    """Fetch an access token for the Keycloak admin user."""
    data = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "username": KEYCLOAK_ADMIN_USER,
        "password": KEYCLOAK_ADMIN_PASSWORD,
        "grant_type": "password"
    }
    
    response = requests.post(KEYCLOAK_TOKEN_URL, data=data)
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        print("Error getting admin token:", response.text)
        return None

if __name__ == "__main__":
    app.run(port=5001, debug=True)
