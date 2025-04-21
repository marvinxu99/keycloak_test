from flask import Flask, redirect, request, session
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.config import SPConfig
from saml2.client import Saml2Client
from saml.config import CONFIG

app = Flask(__name__)
app.secret_key = 'my-secret-key-123456'


def saml_client():
    sp_config = SPConfig()
    sp_config.load(CONFIG)
    return Saml2Client(config=sp_config)


@app.route("/")
def index():
    user_info = session.get("saml_user")
    if user_info:
        name_id = user_info.get("name_id", "Unknown")
        return f"Hello, {name_id}! <br><a href='/logout'>Logout</a>"
    return '<a href="/saml/login">Login with SAML</a>'


@app.route('/saml/login')
def login():
    client = saml_client()
    reqid, info = client.prepare_for_authenticate()
    for key, value in info["headers"]:
        if key == "Location":
            return redirect(value)
    return "No redirect found", 500


@app.route('/saml/acs', methods=['POST'])
def acs():
    client = saml_client()
    saml_response = request.form.get('SAMLResponse')

    authn_response = client.parse_authn_request_response(
        saml_response,
        BINDING_HTTP_POST
    )

    if not authn_response.is_authenticated():
        return "Authentication failed", 403

    session['saml_user'] = {
        "name_id": str(authn_response.name_id),
        "attributes": authn_response.get_identity()
    }

    return f"Login successful.<br>User info:<br>{session['saml_user']}<br><a href='/'>Home</a>"


@app.route('/saml/metadata')
def metadata():
    from saml2.metadata import entity_descriptor
    conf = SPConfig()
    conf.load(CONFIG)
    ed = entity_descriptor(conf)
    return str(ed).encode('utf-8'), 200, {'Content-Type': 'text/xml'}


@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")

@app.route('/saml/sls')
def sls():
    session.clear()
    return "You have been logged out from the service provider."

if __name__ == "__main__":
    app.run(port=5006, debug=True)
