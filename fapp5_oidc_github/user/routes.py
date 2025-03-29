from flask import Blueprint, request, session, redirect, render_template_string, current_app as app
import requests
from user.services import get_keycloak_user_id, get_user_details, update_user_attributes
from auth.utils import get_admin_token

user_bp = Blueprint("user", __name__, url_prefix="/")


@user_bp.route("/welcome")
def welcome():
    if "user_info" not in session:
        return redirect("/")
    
    user_info = session["user_info"]
    return render_template_string("""
        <h2>Welcome, {{ name }} ({{ username }})</h2>
        <p>You have successfully logged into fapp5-oidc-github</p>
        </p>
        <p>Email: {{ email }}</p>
        <div><a href="/logout">Logout</a></div>
        <div><a href="/">Back to Home</a></div>
    """, name=user_info.get("name", "No name"),
         username=user_info.get("preferred_username", "Unknown"),
         email=user_info.get("email", "No email"))


@user_bp.route("/addnew")
def add_user():
    '''Redirect to KeyCloak for adding a new user'''
    # return "Redirect to Keycloak a new user."
    return redirect(f"{app.config['KEYCLOAK_BASE_URL']}/realms/{app.config['REALM_NAME']}/protocol/openid-connect/registrations?client_id=account&response_type=code")


@user_bp.route("/register", methods=["GET", "POST"])
def register_user():
    if request.method == "POST":
        token = get_admin_token()
        if not token:
            return "Error: Could not authenticate with Keycloak", 500

        new_user = {
            "username": request.form.get("username"),
            "email": request.form.get("email"),
            "enabled": True,
            "credentials": [{"type": "password", "value": request.form.get("password"), "temporary": False}],
            "firstName": request.form.get("first_name"),
            "lastName": request.form.get("last_name"),
        }

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = requests.post(app.config["KEYCLOAK_USERS_URL"], json=new_user, headers=headers)

        if response.status_code in [200, 201]:
            return f"<h3>User {new_user['username']} successfully registered!</h3><a href='/'>Back to Home</a>"
        return f"<h3>Error registering user: {response.text}</h3>", response.status_code

    return render_template_string("""
        <h2>Register a New User</h2>
        <form method="POST">
            <label>Username:</label><input type="text" name="username" required><br><br>
            <label>Email:</label><input type="email" name="email" required><br><br>
            <label>Password:</label><input type="password" name="password" required><br><br>
            <label>First Name:</label><input type="text" name="first_name" required><br><br>
            <label>Last Name:</label><input type="text" name="last_name" required><br><br>
            <button type="submit">Register</button>
        </form><br>
        <a href="/">Back to Home</a>
    """)


@user_bp.route("/getproxies")
def get_proxies():
    if "user_info" not in session:
        return redirect("/")

    user_id = get_keycloak_user_id()
    user_data = get_user_details(user_id)
    proxy_phns = user_data.get("attributes", {}).get("Proxies", [])
    if isinstance(proxy_phns, str):
        proxy_phns = [proxy_phns]

    return render_template_string("""
        <h2>PHNs you are a proxy for</h2>
        {% if proxy_phns %}
            <ul>{% for phn in proxy_phns %}<li>{{ phn }}</li>{% endfor %}</ul>
        {% else %}
            <p>You are not currently a proxy for any PHNs.</p>
        {% endif %}
        <a href="/">Back to Home</a>
    """, proxy_phns=proxy_phns)


@user_bp.route("/addproxy")
def add_proxy():
    if "user_info" not in session:
        return redirect("/")

    new_phn = "9876543212"
    user_id = get_keycloak_user_id()
    user_data = get_user_details(user_id)

    proxy_phns = user_data.get("attributes", {}).get("Proxies", [])
    if isinstance(proxy_phns, str):
        proxy_phns = [proxy_phns]

    if new_phn not in proxy_phns:
        proxy_phns.append(new_phn)

    update_user_attributes(user_id, {"Proxies": proxy_phns})

    return f"<p>Added PHN '{new_phn}'</p><a href='/'>Back to Home</a>"


@user_bp.route("/removeproxy", methods=["GET", "POST"])
def remove_proxy():
    if "user_info" not in session:
        return redirect("/")

    user_id = get_keycloak_user_id()
    user_data = get_user_details(user_id)
    proxy_phns = user_data.get("attributes", {}).get("Proxies", [])
    if isinstance(proxy_phns, str):
        proxy_phns = [proxy_phns]

    msg = None
    if request.method == "POST":
        phn_to_remove = request.form.get("phn_to_remove").strip()
        if phn_to_remove in proxy_phns:
            proxy_phns.remove(phn_to_remove)
            update_user_attributes(user_id, {"Proxies": proxy_phns})
            msg = f"Removed PHN '{phn_to_remove}'"
        else:
            msg = f"PHN '{phn_to_remove}' not found."

    return render_template_string("""
        <h2>Remove a Proxy PHN</h2>
        <ul>{% for phn in proxy_phns %}<li>{{ phn }}</li>{% endfor %}</ul>
        {% if msg %}<p><em>{{ msg }}</em></p>{% endif %}
        <form method="POST">
            <label>Enter PHN to remove:</label>
            <input type="text" name="phn_to_remove" required>
            <button type="submit">Remove</button>
        </form>
        <a href="/">Back to Home</a>
    """, proxy_phns=proxy_phns, msg=msg)
