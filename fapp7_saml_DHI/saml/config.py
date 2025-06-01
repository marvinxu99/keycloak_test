import os

# BASE_URL = "http://localhost:5006"  # or your real URL
BASE_URL = "https://6df4-2604-3d08-6882-9500-2828-fa8d-e69b-52de.ngrok-free.app" 
METADATA_FILE = os.path.join(os.path.dirname(__file__), "FederationMetadata.xml")


CONFIG = {
    "entityid": f"{BASE_URL}/saml/metadata",
    "service": {
        "sp": {
            "name": "FlaskSP",
            "endpoints": {
                "assertion_consumer_service": [
                    (f"{BASE_URL}/saml/acs", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
                ],
                "single_logout_service": [
                    (f"{BASE_URL}/saml/sls", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
                ],
            },
            "allow_unsolicited": True,
            "authn_requests_signed": False,
            "logout_requests_signed": False,
            "want_assertions_signed": False,
            "want_response_signed": False,
        }
    },
    "metadata": {
        "local": [METADATA_FILE],
    },
    "key_file": os.path.join(os.path.dirname(__file__), "sp-key.pem"),
    "cert_file": os.path.join(os.path.dirname(__file__), "sp-cert.pem"),
    # "xmlsec_binary": "/usr/bin/xmlsec1",  # change if needed
    "debug": True,
}
