import requests
import os
import json

# --- Configuration ---
# IMPORTANT: Replace with your actual Okta domain.
# For example, if your Okta URL is https://company.okta.com,
# your domain is "company.okta.com".
OKTA_DOMAIN = "demo-demo-intragen-admin.okta.com"

# IMPORTANT: Replace with your Okta API token.
# You can create one in your Okta Admin Dashboard under Security -> API -> Tokens.
# It is highly recommended to store this as an environment variable for security.
# Example: os.environ.get("OKTA_API_TOKEN")
OKTA_API_TOKEN = "00_st8N-sRDvZ6x9apI9lQPc96qor8ooZEzUqvVcHt" 

# --- API Request Details ---
# These are the parameters for your log request.
# You can modify the dates or the query as needed.
PARAMS = {
    'since': '2025-07-13T21:00:00Z',
    'until': '2025-07-21T20:59:59Z',
    'q': '' 
}

# The name of the file where the logs will be saved.
# Note: The standard Okta Log API returns JSON, not CSV.
OUTPUT_FILENAME = "okta_logs.json"

def download_okta_logs():
    """
    Connects to the official Okta API to download system logs as a JSON file.
    """
    if OKTA_API_TOKEN == "YOUR_API_TOKEN_HERE":
        print("Error: Please replace 'YOUR_API_TOKEN_HERE' with your actual Okta API token.")
        return

    # Construct the full API endpoint URL for the documented System Log API.
    # The /sage/ endpoint you were using is likely internal and not for public use.
    # The correct, documented public API is /api/v1/logs.
    url = f"https://{OKTA_DOMAIN}/api/v1/logs"

    # Set up the required headers for the API request.
    # The 'Authorization' header uses the 'SSWS' scheme for API tokens.
    # The standard API returns JSON, so we set the Accept header accordingly.
    headers = {
        'Accept': 'application/json',
        'Authorization': f'SSWS {OKTA_API_TOKEN}'
    }

    print(f"Sending request to the official Okta Log API: {url}")
    print(f"With parameters: {PARAMS}")

    try:
        # Make the GET request to the Okta API
        response = requests.get(url, headers=headers, params=PARAMS)

        # Raise an exception for bad status codes (4xx or 5xx)
        response.raise_for_status()

        # If the request is successful, parse the JSON response.
        # The response from this endpoint is a JSON array of log events.
        logs_data = response.json()
        
        # Save the JSON data to a file in a human-readable format.
        with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
            json.dump(logs_data, f, ensure_ascii=False, indent=4)
        
        print(f"\nSuccess! Logs have been downloaded and saved to '{OUTPUT_FILENAME}'.")
        print("\nNote: The data is in JSON format. To convert this to CSV, you could use a library like pandas:")
        print("  import pandas as pd")
        print("  df = pd.read_json('okta_logs.json')")
        print("  df.to_csv('okta_logs_converted.csv', index=False)")

    except requests.exceptions.HTTPError as errh:
        print(f"\nHTTP Error: {errh}")
        print(f"Response Status Code: {errh.response.status_code}")
        print(f"Response Body: {errh.response.text}")
        if errh.response.status_code == 401:
            print("\nAuthentication failed (401 Unauthorized). Please check that your OKTA_DOMAIN and OKTA_API_TOKEN are correct and that the token has the required permissions (okta.logs.read).")
    except requests.exceptions.ConnectionError as errc:
        print(f"\nError Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"\nTimeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"\nAn unexpected error occurred: {err}")

if __name__ == "__main__":
    download_okta_logs()
