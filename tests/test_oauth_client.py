import requests
import requests_mock
from flask import session
from flask_testing import TestCase
from oauth2_lib.oauth_client import add_access_token_header, add_oauth_remote, reload_authentication
from tests.utils import create_test_app

ENVIRON_BASE = {"HTTP_AUTHORIZATION": "bearer test"}

OAUTH2_BASE_URL = "http://authz-server"


class TestOAuthClient(TestCase):
    def create_app(self):
        app = create_test_app()
        add_oauth_remote(
            app, "http://localhost", OAUTH2_BASE_URL, "core-admin", "secret", "http://localhost/oauth2/callback"
        )
        return app

    def tearDown(self):
        requests.Session().close()

    @requests_mock.Mocker()
    def test_missing_write_scope_for_write_endpoints(self, m):
        m.get(OAUTH2_BASE_URL + "/oauth2_lib/authorize")
        response = self.client.post("/hello", environ_base=ENVIRON_BASE)
        self.assertEqual(302, response.status_code)
        self.assertEqual(
            response.headers.get("Location"),
            "http://authz-server/authorize?response_type=code&state=http%3A//localhost/hello&"
            "client_id=core-admin&scope=read+write+admin&redirect_uri=http://localhost/oauth2/callback",
        )

        m.post(OAUTH2_BASE_URL + "/token", json={"access_token": "access_token", "refresh_token": "refresh_token"})
        m.get(OAUTH2_BASE_URL + "/introspect", json={"name": "john.doe"})
        response = self.client.get("/oauth2/callback?code=secret&state=http%3A//localhost/hello")
        self.assertEqual(302, response.status_code)
        self.assertEqual(response.headers.get("Location"), "http://localhost/hello")

    def test_add_access_header(self):
        session["auth_tokens"] = ("access_token", "refresh_token")
        client = add_access_token_header({})
        self.assertEqual("bearer access_token", client.request_headers["Authorization"])

    def test_reload_authentication(self):
        session["some"] = "thing"
        response = reload_authentication()
        self.assertEqual(302, response.status_code)
        self.assertEqual("http://localhost", response.headers["Location"])
        self.assertEqual(0, len(session.items()))
