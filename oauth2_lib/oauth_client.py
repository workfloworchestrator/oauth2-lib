from urllib import parse

import requests
from flask import Blueprint, current_app, redirect, request, session
from oauth2_lib.api_client import ApiClientProxy
from werkzeug.exceptions import Unauthorized
from werkzeug.wrappers import Response

REDIRECT_STATE = "redirect_state"
AUTH_SERVER = "oauth2_server"
SCOPES = ["read", "write", "admin"]

oauth2 = Blueprint("oauth2", __name__, url_prefix="/oauth2")

req_session = requests.Session()


def add_oauth_remote(app, client_base_url, oauth2_base_url, oauth2_client_id, oauth2_secret, oauth2_callback_url):
    app.config[AUTH_SERVER] = {
        "client_base_url": client_base_url,
        "oauth2_client_id": oauth2_client_id,
        "oauth2_secret": oauth2_secret,
        "check_token_url": oauth2_base_url + "/introspect",
        "access_token_url": oauth2_base_url + "/token",
        "authorize_url": oauth2_base_url + "/authorize",
        "callback_url": oauth2_callback_url,
    }

    def force_authorize():
        config = current_app.config[AUTH_SERVER]
        intended_url = f"{client_base_url}{request.path}"
        redirect_url = config["callback_url"]
        if not session.get("user") and intended_url != redirect_url:
            state = parse.quote(intended_url)
            session[REDIRECT_STATE] = state
            full_authorization_url = (
                f"{config['authorize_url']}?"
                f"response_type=code&"
                f"state={state}&"
                f"client_id={config['oauth2_client_id']}&"
                f"scope={'+'.join(SCOPES)}&"
                f"redirect_uri={redirect_url}"
            )
            return redirect(full_authorization_url)

    app.register_blueprint(oauth2)
    app.before_request(force_authorize)


@oauth2.route("/callback")
def callback():
    stored_state = session.get(REDIRECT_STATE)
    callback_state = request.args.get("state")
    if not stored_state or parse.unquote(stored_state) != callback_state:
        raise Unauthorized(description=f"State does not match: {stored_state} vs {callback_state}")

    session.pop(REDIRECT_STATE, None)
    config = current_app.config[AUTH_SERVER]

    data = {
        "code": request.args.get("code"),
        "redirect_uri": config["callback_url"],
        "grant_type": "authorization_code",
    }

    auth = (config["oauth2_client_id"], config["oauth2_secret"])
    response = req_session.post(
        url=config["access_token_url"],
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        auth=auth,
        timeout=5,
    )
    if not response.ok:
        raise_unauthorized(response, "obtaining access_token")

    json = response.json()
    session["auth_tokens"] = (json["access_token"], json["refresh_token"])

    response = req_session.get(
        url=config["check_token_url"], params={"token": json["access_token"]}, auth=auth, timeout=5
    )
    if not response.ok:
        raise_unauthorized(response, "token validation")

    session["user"] = response.json()

    return redirect(callback_state)


def raise_unauthorized(response, action):
    description = f"Response for {action} {response.json()}"
    raise Unauthorized(description=description)


def add_access_token_header(client):
    auth_tokens = session.get("auth_tokens")
    if auth_tokens:
        access_token = auth_tokens[0]
        return ApiClientProxy(client, {"Authorization": f"bearer {access_token}"})
    return client


def reload_authentication():
    session.clear()
    response = Response("<!DOCTYPE html>", 302, mimetype="text/html")
    location = current_app.config[AUTH_SERVER]["client_base_url"]
    response.headers["Location"] = location
    return response


def get_user():
    return session["user"] if "user" in session else {}
