from flask import Flask, redirect, request, session, url_for
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.config import Config as Saml2Config
from saml2.client import Saml2Client
from saml2.metadata import entity_descriptor
from saml2.saml import NameID
import os

app = Flask(__name__)
app.secret_key = "your_secret_key123456789"

# SAML Configuration
SAML_METADATA_URL = "http://localhost:8080/realms/MyRealm/protocol/saml/descriptor"
# SAML_SP_ENTITY_ID = "http://localhost:5003"
SAML_SP_ENTITY_ID = "fapp3"
SAML_ACS_URL = "http://localhost:5003/saml/acs"
SAML_LOGOUT_URL = "http://localhost:5003/logout"
SAML_IDP_ENTITY_ID = "http://localhost:8080/realms/MyRealm"

# Use a local metadata file to avoid Keycloak metadata fetching issues
SAML_METADATA_FILE = "keycloak-metadata.xml"

if not os.path.exists(SAML_METADATA_FILE):
    import requests
    response = requests.get(SAML_METADATA_URL)
    if response.status_code == 200:
        with open(SAML_METADATA_FILE, "wb") as f:
            f.write(response.content)
    else:
        print("Failed to fetch SAML metadata. Check Keycloak.")

def saml_client():
    """Create a SAML2 Client"""
    config = Saml2Config()
    config.load({
        "entityid": SAML_SP_ENTITY_ID,
        "metadata": {"local": [SAML_METADATA_FILE]},
        "service": {
            "sp": {
                "allow_unknown_attributes": True,
                "authn_requests_signed": False,     # Disable signed requests (for dev)
                "want_response_signed": False,      # Disable signed responses (for dev)
                "want_assertions_signed": False,    # Disable signed assertions
                "logout_requests_signed": False,    # Disable signed logout requests
                "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:username",
                "logout_requests_signed": False,     # Disable signed logout requests
                "force_authn": False,                # Disable forced authentication
                "allow_unsolicited": True,          # Allow unsolicited responses
                "endpoints": {
                    "assertion_consumer_service": [(SAML_ACS_URL, BINDING_HTTP_POST)],
                    "single_logout_service": [(SAML_LOGOUT_URL, BINDING_HTTP_POST)],
                },
                "accepted_time_diff": 300,  # Allows 5 minutes time difference
            }
        },
    })
    return Saml2Client(config)


@app.route("/")
def home():
    return '<a href="/login">Login with SAML</a>'


@app.route("/login")
def login():
    client = saml_client()

    # Use the realm entity ID from Keycloak metadata
    idp_entity_id = SAML_IDP_ENTITY_ID

    # Prepare authentication request
    reqid, info = client.prepare_for_authenticate(entityid=idp_entity_id, binding=BINDING_HTTP_REDIRECT)
    
    # Extract redirect URL
    redirect_url = dict(info["headers"])["Location"]

    # Debugging output
    print(f"Redirecting to: {redirect_url}")
    print(f"SAML Request: {request.args.get('SAMLRequest')}")

    return redirect(redirect_url)


@app.route("/saml/acs", methods=["POST"])   # ACS - Assertion Consumer Service
def saml_acs():
    client = saml_client()
    authn_response = client.parse_authn_request_response(request.form["SAMLResponse"], BINDING_HTTP_POST)
    if authn_response is None or authn_response.get_subject() is None:
        return "Authentication failed.", 401

    # Extract the full NameID object
    subject = authn_response.get_subject()

    session["user"] = subject.text

    # Store the full NameID in session
    session["name_id"] = subject.text
    session["name_id_format"] = subject.format
    session["name_id_sp_name_qualifier"] = subject.sp_name_qualifier if subject.sp_name_qualifier else ""

    # Also, store the session index (if available) for SLO purposes
    session_id = authn_response.session_id()
    if session_id:
        session["session_id"] = session_id

    print(f"Stored NameID: {session['name_id']}, Format: {session['name_id_format']}, "
          f"Session Index: {session.get('session_id')}")

    return f"Authenticated as: {session['user'], session['name_id']} <a href='/logout'>Logout</a>"


@app.route("/saml/metadata")
def saml_metadata():
    client = saml_client()
    metadata_str = str(entity_descriptor(client.config))
    return metadata_str, 200, {'Content-Type': 'text/xml'}


@app.route("/logout")
def logout():
    if "name_id" in session:
        client = saml_client()

        # Retrieve NameID attributes from session
        name_id = session["name_id"]
        name_id_format = session.get("name_id_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
        sp_name_qualifier = session.get("name_id_sp_name_qualifier", "")
        session_id = session.get("session_id")  # Keycloak SAML session index

        # Construct the NameID object for logout
        #name_id_obj = NameID(format=name_id_format, sp_name_qualifier=sp_name_qualifier, text=name_id)
        name_id_obj = NameID(format=name_id_format, text=name_id)

        print("Metadata keys loaded:", client.metadata.keys())
        print(f"Logging out user: {name_id}, Format: {name_id_format}, SP Name Qualifier: {sp_name_qualifier}, Session ID: {session_id}")

        # Ensure Keycloak's SAML logout endpoint is used
        slo_destination = "http://localhost:8080/realms/MyRealm/protocol/saml"

        try:
            # Required parameters for do_logout()
            entity_ids = [SAML_IDP_ENTITY_ID]  # The IdP entity ID
            expire = None  # Log out immediately

            # Generate the logout request with session index
            logout_request = client.do_logout(
                name_id=name_id_obj,
                session_id=session_id if session_id else "",
                entity_ids=entity_ids,
                expire=expire,
                reason="User Logout",
                sign=None
            )

            # Print out the LogoutRequest object details
            print("\n **Logout Request Sent:**")
            print(f"Type: {type(logout_request)}")
            print(f"Content: {logout_request}")

            # Extract the actual LogoutResponse
            logout_response = logout_request.get(SAML_IDP_ENTITY_ID, None)
            if logout_response:
                print("\n **LogoutResponse Details:**")
                print(f"Status Code: {logout_response.status}")
                print(f"Issuer: {logout_response.issuer}")
                print(f"Destination: {logout_response.destination}")
                print(f"InResponseTo: {logout_response.in_response_to}")

            # Ensure the response is valid
            logout_url = None
            for binding, header_info in logout_request.items():
                if binding == BINDING_HTTP_REDIRECT:
                    logout_url = dict(header_info).get("Location")
                    break

            if logout_url:
                print(f"Redirecting to SLO URL: {logout_url}")
                session.clear()
                return redirect(logout_url)
            else:
                print("No logout URL found, manually redirecting to Keycloak logout.")
                session.clear()
                return redirect(slo_destination)

        except Exception as e:
            print("Error generating LogoutRequest:", e)
            session.clear()
            return "Logout failed on the SAML side. Please close your browser to complete logout from Keycloak.", 500

    # Fallback: if no SAML session info is available, clear session and redirect home
    session.clear()
    return redirect(url_for("home"))



if __name__ == "__main__":
    app.run(port=5003, debug=True)
