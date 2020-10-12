import requests
import requests_mock
from flask_testing import TestCase

from oauth2_lib.oauth_credentials import (
    AUTH_RESOURCE_SERVER,
    add_client_credentials_token_header,
    obtain_client_credentials_token,
    refresh_client_credentials_token,
)
from tests.utils import create_test_app

OAUTH2_TOKEN_URL = "http://authz-server/oauth/token"  # noqa: S105


class TestOAuthCredentials(TestCase):
    def create_app(self):
        app = create_test_app()
        return app

    def tearDown(self):
        requests.Session().close()

    @requests_mock.Mocker()
    def test_client_credentials_token_flow(self, m):
        json = {"access_token": "token", "token_type": "bearer", "expires_in": 15498128, "scope": "read  write  admin"}
        m.post(OAUTH2_TOKEN_URL, json=json)
        obtain_client_credentials_token(self.app, OAUTH2_TOKEN_URL, "client_id", "secret")
        self.assertEqual(self.app.config[AUTH_RESOURCE_SERVER]["access_token"], "token")

        client = add_client_credentials_token_header({}, self.app)
        self.assertEqual("bearer token", client.request_headers["Authorization"])

        json["access_token"] = "new_token"  # noqa: S105
        m.post(OAUTH2_TOKEN_URL, json=json)

        refresh_client_credentials_token(self.app)
        self.assertEqual(self.app.config[AUTH_RESOURCE_SERVER]["access_token"], "new_token")
