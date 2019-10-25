#  Copyright 2019 SURF.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


import uuid
from pathlib import Path

import flask
import requests
import requests_mock
from flask_testing import TestCase
from oauth2_lib.oauth_filter import OAuthFilter
from ruamel.yaml import YAML

ENVIRON_BASE = {"HTTP_AUTHORIZATION": "bearer test"}

TOKEN_CHECK_URL = "http://authz-server/token_check"  # noqa: S105

JOHN_DOE = {
    "active": True,
    "authenticating_authority": "https://www.onegini.me",
    "client_id": "https@//orchestrator.automation.surf.net",
    "display_name": "John Doe",
    "edu_person_principal_name": "j.doe@example.com",
    "edumember_is_member_of": [],
    "eduperson_entitlement": [],
    "email": "j.doe@example.com",
    "exp": 1524223869,
    "expires_at": "2018-04-20T13:31:09+0200",
    "given_name": "John Doe",
    "schac_home": "surfguest.nl",
    "scope": "nwa-cert-r nwa-lir-r",
    "sub": "1f1891bf-a9be-3fcd-b669-93f6de70ee11",
    "sur_name": "Doe",
    "token_type": "Bearer",
    "unspecified_id": "urn:collab:person:surfguest.nl:jdoe",
    "user_id": "1f1891bf-a9be-3fcd-b669-93f6de70ee11",
}

CUSTOMER_ID = uuid.uuid4()


def create_test_app():
    app = flask.Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "secret"
    app.debug = True

    @app.route("/dashboard/subscriptions/IP")
    def subscriptions_ip():
        return "All IP subscriptions"

    return app


@requests_mock.Mocker()
class TestOAuthFilter(TestCase):
    def create_app(self):
        app = create_test_app()
        with (Path(__file__).parent / "scoping_issue_nw_dashboard_sec_def.yaml").open() as file:
            yaml = YAML(typ="safe")
            security_definitions = yaml.load(file)
            app.before_request(
                OAuthFilter(security_definitions, TOKEN_CHECK_URL, "coredb", "secret", ["config"], False).filter
            )
            return app

    def tearDown(self):
        requests.Session().close()

    def test_subscriptions_endpoint_both_scopes(self, m):
        m.get(TOKEN_CHECK_URL, json=JOHN_DOE, status_code=200)
        response = self.client.get("/dashboard/subscriptions/IP", environ_base=ENVIRON_BASE)
        self.assertEqual(200, response.status_code)

    def test_subscriptions_endpoint_nwa_cert_r(self, m):
        john_doe = dict(JOHN_DOE)
        john_doe.update(scope="nwa-cert-r")
        m.get(TOKEN_CHECK_URL, json=john_doe, status_code=200)
        response = self.client.get("/dashboard/subscriptions/IP", environ_base=ENVIRON_BASE)
        self.assertEqual(200, response.status_code)

    def test_subscriptions_endpoint_nwa_lir_r(self, m):
        john_doe = dict(JOHN_DOE)
        john_doe.update(scope="nwa-lir-r")
        m.get(TOKEN_CHECK_URL, json=john_doe, status_code=200)
        response = self.client.get("/dashboard/subscriptions/IP", environ_base=ENVIRON_BASE)
        self.assertEqual(200, response.status_code)
