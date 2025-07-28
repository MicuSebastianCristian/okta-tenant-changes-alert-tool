import requests
import json
import time
import uuid
from jose import jwt
from pathlib import Path

# --- Configurare ---
OKTA_DOMAIN = "demo-demo-intragen.okta.com"
CLIENT_ID = "0oat4kc3vw3Ih3iPz697"
PRIVATE_KEY_PATH = "keys/private_key.pem"
KID = "dcc-policy-key-1"
TOKEN_URL = f"https://{OKTA_DOMAIN}/oauth2/v1/token"
SCOPES = "okta.policies.read okta.apps.read okta.logs.read"

# Add flag to optionally use a pre-generated SSWS API token instead of JWT client-credentials flow
USE_STATIC_TOKEN = True  # Set to True to use the STATIC_TOKEN below and skip JWT flow
STATIC_TOKEN = "00_st8N-sRDvZ6x9apI9lQPc96qor8ooZEzUqvVcHt"  # <-- replace with your actual Okta API token

# ----------------------------------------------------------------------------
# Obtain access token
# ----------------------------------------------------------------------------
if USE_STATIC_TOKEN:
    print("Using static SSWS token provided in STATIC_TOKEN variable...")
    access_token = STATIC_TOKEN
    token_type = "SSWS"
else:
    # --- Construire JWT assertion ---
    private_key = Path(PRIVATE_KEY_PATH).read_bytes()
    now = int(time.time())
    assertion = jwt.encode(
        {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": TOKEN_URL,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": KID},
    )

    # --- Cerere token ---
    payload = {
        "grant_type": "client_credentials",
        "scope": SCOPES,
        "client_id": CLIENT_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    print(f">>> Trimitere cerere către: {TOKEN_URL}")
    try:
        response = requests.post(TOKEN_URL, data=payload, headers=headers)
        if response.status_code == 200:
            print("\n✅ Cerere reușită! Token obținut.")
            token_data = response.json()
            print(json.dumps(token_data, indent=4))
            access_token = token_data["access_token"]
            token_type = "Bearer"
        else:
            print(f"\n❌ Eroare! Status Code: {response.status_code}")
            print("Răspuns de la server:")
            print(response.text)
            raise SystemExit(1)
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Eroare de rețea sau de conectare: {e}")
        raise SystemExit(1)

# ----------------------------------------------------------------------------
# Test Management API call with obtained/provided token
# ----------------------------------------------------------------------------
api_url = f"https://{OKTA_DOMAIN}/api/v1/policies"
api_headers = {"Authorization": f"{token_type} {access_token}"}
api_params = {"type": "OKTA_SIGN_ON"}
print(f"\n>>> Call către {api_url} cu token-ul...")
api_resp = requests.get(api_url, headers=api_headers, params=api_params)
print(f"Status: {api_resp.status_code}")
print("Body:")
print(api_resp.text)