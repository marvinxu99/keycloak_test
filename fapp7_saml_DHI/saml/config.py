import os

BASE_URL = "http://localhost:5006"  # or your real URL
# BASE_URL = "https://your.real.portal.url"

METADATA_FILE = os.path.join(os.path.dirname(__file__), "Metadata.xml")

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
                    # Optionally add POST binding too, since IdP supports it:
                    # (f"{BASE_URL}/saml/sls", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
                ],
            },
            "allow_unsolicited": True,        # Support IdP-initiated SSO (e.g. from Health Gateway)
            "authn_requests_signed": False,   # True,  # REQUIRED by IdP metadata (WantAuthnRequestsSigned=true)
            "logout_requests_signed": False,  # True,  # Good practice if you're using SLO
            "want_assertions_signed": False,  #True,  # Strongly recommended
            "want_response_signed": False,    # Optional - most IdPs sign assertions only
        }
    },
    "metadata": {
        "local": [METADATA_FILE],
    },
    "key_file": os.path.join(os.path.dirname(__file__), "sp-key.pem"),
    "cert_file": os.path.join(os.path.dirname(__file__), "sp-cert.pem"),
    # "xmlsec_binary": "C:/xmlsec/xmlsec/bin/xmlsec.exe",  # adjust if needed
    "debug": True,
}
