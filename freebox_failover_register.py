#!/usr/bin/env python3
"""Register and authenticate the Freebox Failover daemon with Freebox OS.

This helper script obtains and stores an application token, then opens a
session with the Freebox HTTP API and prints whether the session token
was successfully initialized.
"""
import os
import io
import sys
import hmac
import time
import json
import hashlib
import configparser
import argparse
import requests

APP_ID		= "free_wifi_gateway"
APP_NAME	= "Free Wifi Gateway"
APP_VERSION	= "0.0.1"
DEVICE_NAME	= "linux"

parser = argparse.ArgumentParser(
    description="Freebox Failover Daemon Registering Helper"
)


parser.add_argument(
    "-c", "--config",
    default="/etc/freebox_failover.conf",
    help="Path to configuration file (default: /etc/freebox_failover.conf)"
)

parser.add_argument(
    "-t", "--token-file",
    default=None,
    help="Path to Freebox app token JSON file (overrides 'token_file' in config)."
)

args = parser.parse_args()

config = configparser.ConfigParser()
config.read(args.config)

if 'freebox' not in config:
    print("Missing [freebox] section in config file", file=sys.stderr)
    sys.exit(1)

freebox_cfg = config['freebox']
TOKEN_FILE	= args.token_file or freebox_cfg.get('token_file')
FREEBOX_IP  = freebox_cfg.get('ip')

if not TOKEN_FILE or not FREEBOX_IP:
    print("token_file or ip missing in config/CLI", file=sys.stderr)
    sys.exit(1)

API_URL		= f"http://{FREEBOX_IP}/api/v8"

def load_app_token():
    """Load persisted Freebox application token and track_id from disk.

    Returns
    -------
    tuple[str|None, str|None]
        (app_token, track_id) if present; (None, None) otherwise.
    """
    if not os.path.exists(TOKEN_FILE):
        return None, None

    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data["app_token"], data["track_id"]
    except (json.JSONDecodeError, KeyError) as exc:
        print(f"Token file invalid ({TOKEN_FILE}): {exc}. Delete and re-register.",
              file=sys.stderr)
        return None, None

def save_app_token(app_token, track_id):
    """Persist Freebox application token and track_id to disk.

    Parameters
    ----------
    app_token : str
        Token issued by the Freebox authorization step.
    track_id : str
        Tracking identifier returned by the authorization API.
    """
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with io.open(fd, "w", encoding="utf-8") as file:
        json.dump({"app_token": app_token, "track_id": track_id}, file)

def api_request(method, endpoint, session_token=None, **kwargs):
    """Call a Freebox OS API endpoint and return its `result` payload.

    Parameters
    ----------
    method : str
        HTTP verb, e.g. 'get', 'post'.
    endpoint : str
        API path beginning with '/'.
    session_token : str | None
        Optional session token to send as 'X-Fbx-App-Auth'.
    **kwargs : dict
        Extra arguments forwarded to `requests.request` (json=data, params, etc.).

    Returns
    -------
    Any | str | None
        The `result` field on success; the string 'forbidden' on HTTP 403;
        or None on network/JSON errors.
    """
    headers = {}
    if session_token:
        headers["X-Fbx-App-Auth"] = session_token

    try:
        response = requests.request(method, f"{API_URL}{endpoint}", headers=headers,
                                    timeout=5, **kwargs)
        response.raise_for_status()
        data = response.json()
        if data.get('success'):
            return data.get('result')
        print(f"API Error on {endpoint}: {data.get('msg')}", file=sys.stderr)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            return "forbidden" # Return a special string for 403 errors
        print(f"HTTP Error on {endpoint}: {e}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"Network Error on {endpoint}: {e}", file=sys.stderr)
    except json.JSONDecodeError:
        print(f"JSON Decode Error on {endpoint}", file=sys.stderr)
    return None

def freebox_connect():
    """Establish a Freebox OS API session token.

    1) Load stored app token/track_id; otherwise request authorization and poll
       until the user approves the app on the Freebox.
    2) Compute HMAC-SHA1 password from challenge and app_token.
    3) Open a login session and return the session token.

    Returns
    -------
    str | None
        A valid session token, or None if the flow fails.
    """
    app_token, track_id = load_app_token()
    if not app_token or not track_id:
        auth_data = api_request("post", "/login/authorize/", json={
            "app_id": APP_ID, "app_name": APP_NAME,
            "app_version": APP_VERSION, "device_name": DEVICE_NAME
        })
        if not auth_data:
            return None
        track_id, app_token = auth_data['track_id'], auth_data['app_token']
        save_app_token(app_token, track_id)
        print("Veuillez accepter l'application sur la Freebox")
        max_retries = 24
        for _ in range(max_retries):
            status_data = api_request("get", f"/login/authorize/{track_id}")
            status = status_data.get('status') if status_data else None
            if status == 'granted':
                print("Authorization granted.")
                break
            if status == 'pending':
                print("Waiting for authorization...")
                time.sleep(5)
            else:
                print(f"Authorization failed with status: {status}")
                return None
        else:
            print("Authorization polling timed out after 2 minutes.")
            return None

    challenge_data = api_request("get", f"/login/authorize/{track_id}")
    if not challenge_data or not isinstance(challenge_data, dict):
        print("Failed to get challenge, token might be invalid.")
        return None
    challenge = challenge_data['challenge']
    password = hmac.new(app_token.encode(), challenge.encode(), hashlib.sha1).hexdigest()

    login_data = api_request("post", "/login/session/",
                             json={"app_id": APP_ID, "password": password})
    if login_data == "forbidden":
        print("Login forbidden – app_token probably revoked.",
              "Delete token file and retry.", file=sys.stderr)
        return None

    if not isinstance(login_data, dict):
        print("Unexpected login response format", file=sys.stderr)
        return None

    return login_data['session_token'] if login_data else None

def main():
    """Entry point: connect to the Freebox and display session status."""
    session_token = freebox_connect()
    if not session_token:
        print("Could not connect to Freebox. Exiting.")
        return

    print("Session token correctly initialized")

if __name__ == "__main__":
    main()
