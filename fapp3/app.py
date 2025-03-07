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
                "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "logout_requests_signed": False,     # Disable signed logout requests
                "force_authn": False,                # Disable forced authentication
                "allow_unsolicited": True,          # Allow unsolicited responses
                "endpoints": {
                    "assertion_consumer_service": [(SAML_ACS_URL, BINDING_HTTP_POST)],
                    "single_logout_service": [(SAML_LOGOUT_URL, BINDING_HTTP_POST)],
                },
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

    # Get first IdP entity ID from metadata
    # idp_keys = list(client.metadata.keys())
    # if not idp_keys:
    #     return "No IdP found in metadata.", 500
    # idp_entity_id = idp_keys[0]
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


@app.route("/saml/acs", methods=["POST"])
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
        session_id = session.get("session_id")

        # Construct the NameID object for logout
        name_id_obj = NameID(format=name_id_format, sp_name_qualifier=sp_name_qualifier, text=name_id)
        print("Metadata keys loaded:", client.metadata.keys())
        print(f"Logging out user: {name_id}, Format: {name_id_format}, SP Name Qualifier: {sp_name_qualifier}, Session ID: {session_id}")

        try:
            # Try to perform global logout via pysaml2 using just the NameID
            reqid, info = client.global_logout(name_id_obj)
        except Exception as e:
            print("Error calling global_logout:", e)
            # Fallback: Attempt to retrieve the IdP's SLO endpoint from metadata
            try:
                slo_endpoints = client.metadata.single_logout_service(SAML_IDP_ENTITY_ID, binding=BINDING_HTTP_REDIRECT, typ="logout_request")
                slo_destination = slo_endpoints[0][1] if slo_endpoints else None
            except Exception as e2:
                print("Error retrieving SLO endpoint from metadata:", e2)
                slo_destination = None

            if not slo_destination:
                # Fallback to hard-coded Keycloak SLO endpoint as defined in your metadata
                slo_destination = "http://localhost:8080/realms/MyRealm/protocol/saml"
            session.clear()
            return redirect(slo_destination)

        # Extract redirect URL from the generated LogoutRequest info (using HTTP-Redirect binding)
        logout_url = None
        for binding, header_info in info.items():
            if binding == BINDING_HTTP_REDIRECT:
                logout_url = dict(header_info).get("Location")
                break

        if logout_url:
            session.clear()
            return redirect(logout_url)

    # Fallback: if no SAML session info is available, clear the session and redirect to home
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(port=5003, debug=True)
