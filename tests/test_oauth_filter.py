import os
import uuid

import requests
import requests_mock
from flask_testing import TestCase
from oauth2_lib.oauth_filter import OAuthFilter
from ruamel.yaml import YAML
from tests.utils import create_test_app

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
    "scope": "read write",
    "sub": "1f1891bf-a9be-3fcd-b669-93f6de70ee11",
    "sur_name": "Doe",
    "token_type": "Bearer",
    "unspecified_id": "urn:collab:person:surfguest.nl:jdoe",
    "user_id": "1f1891bf-a9be-3fcd-b669-93f6de70ee11",
}

CUSTOMER_ID = uuid.uuid4()


@requests_mock.Mocker()
class TestOAuthFilter(TestCase):
    def create_app(self):
        app = create_test_app()
        with open(os.path.join(os.path.dirname(__file__), "security_definitions.yaml")) as file:
            yaml = YAML(typ="safe")
            security_definitions = yaml.load(file)
            app.before_request(
                OAuthFilter(security_definitions, TOKEN_CHECK_URL, "coredb", "secret", ["config"], False).filter
            )
            return app

    def tearDown(self):
        requests.Session().close()

    def test_no_token(self, m):
        self._check(
            m,
            environ_base={},
            response_status_code=401,
            response_detail="401 Unauthorized: No Authorization token provided",
        )

    def test_invalid_header(self, m):
        self._check(
            m,
            environ_base={"HTTP_AUTHORIZATION": "nope"},
            response_status_code=401,
            response_detail="401 Unauthorized: Invalid authorization header: nope",
        )

    def test_invalid_token(self, m):
        self._check(
            m,
            status_code=400,
            response_status_code=401,
            response_detail="401 Unauthorized: Provided oauth2 token is not valid: test",
        )

    def test_whitelisted_endpoints(self, m):
        m.post(TOKEN_CHECK_URL, status_code=500)
        response = self.client.get("/config")
        self.assertEqual(200, response.status_code)

    def test_allow_cors_calls(self, m):
        response = self.client.options("/hello")
        self.assertEqual(200, response.status_code)

    def test_restricted_endpoint_allow(self, m):
        entitlements = ["urn:mace:surfnet.nl:surfnet.nl:sab:role:Infraverantwoordelijke"]
        m.post(TOKEN_CHECK_URL, json={**JOHN_DOE, "eduperson_entitlement": entitlements}, status_code=200)
        response = self.client.get("/restricted/endpoint", environ_base=ENVIRON_BASE)

        self.assertEqual(200, response.status_code)
        self.assertEqual(b"You are an Infraverantwoordelijke of an institution", response.data)

    def test_restricted_endpoint_deny(self, m):
        m.post(TOKEN_CHECK_URL, json=JOHN_DOE, status_code=200)
        response = self.client.get("/restricted/endpoint", environ_base=ENVIRON_BASE)

        self.assertEqual(403, response.status_code)

    def test_onlyfor_infrabeheerder_allow(self, m):
        entitlements = ["urn:mace:surfnet.nl:surfnet.nl:sab:role:Infrabeheerder"]
        m.post(TOKEN_CHECK_URL, json={**JOHN_DOE, "eduperson_entitlement": entitlements}, status_code=200)
        response = self.client.get("/onlyfor/infrabeheerder", environ_base=ENVIRON_BASE)
        self.assertEqual(200, response.status_code)
        self.assertEqual(b"You are an Infrabeheerder", response.data)

    def test_onlyfor_infrabeheerder_deny(self, m):
        m.post(TOKEN_CHECK_URL, json=JOHN_DOE, status_code=200)
        response = self.client.get("/onlyfor/infrabeheerder", environ_base=ENVIRON_BASE)
        self.assertEqual(403, response.status_code)
        self.assertIn("ROLE", response.json["detail"])

    def test_customer_id_deny(self, m):
        m.post(TOKEN_CHECK_URL, json=JOHN_DOE, status_code=200)
        response = self.client.get("/customer/{}".format(CUSTOMER_ID), environ_base=ENVIRON_BASE)
        self.assertEqual(403, response.status_code)
        self.assertIn("Parameter customerId in the request path", response.json["detail"])

    def test_wildcard(self, m):
        teams = ["urn:collab:group:surfteams.nl:nl:surfnet:diensten:noc_superuserro_team_for_netwerkdashboard"]
        m.post(TOKEN_CHECK_URL, json={**JOHN_DOE, "edumember_is_member_of": teams}, status_code=200)
        response = self.client.get("/cert_endpoint", environ_base=ENVIRON_BASE)
        self.assertEqual(200, response.status_code)

    def test_invalid_wildcard(self, m):
        scope = "WRONG_SCOPE"
        m.post(TOKEN_CHECK_URL, json={**JOHN_DOE, "scope": scope}, status_code=200)
        response = self.client.get("/cert_endpoint", environ_base=ENVIRON_BASE)
        self.assertEqual(403, response.status_code)

    def test_cert_only(self, m):
        scope = "nwa-cert"
        m.post(TOKEN_CHECK_URL, json={**JOHN_DOE, "scope": scope}, status_code=200)
        response = self.client.get("/cert_endpoint", environ_base=ENVIRON_BASE)
        self.assertEqual(200, response.status_code)
        response = self.client.get("/customer/{}".format(CUSTOMER_ID), environ_base=ENVIRON_BASE)
        self.assertEqual(403, response.status_code)

    def test_customer_id_allow(self, m):
        entitlements = ["urn:mace:surfnet.nl:surfnet.nl:sab:organizationGUID:{}".format(CUSTOMER_ID)]
        m.post(TOKEN_CHECK_URL, json={**JOHN_DOE, "eduperson_entitlement": entitlements}, status_code=200)

    def _check(
        self, m, json=None, status_code=200, environ_base=ENVIRON_BASE, response_status_code=200, response_detail=None
    ):
        m.post(TOKEN_CHECK_URL, json=json, status_code=status_code)
        response = self.client.get("/hello", environ_base=environ_base)

        self.assertEqual(response_status_code, response.status_code)

        if response_status_code != 200:
            self.assertEqual(response_detail, response.json["detail"])
            self.assertEqual(None, OAuthFilter.current_user())
        else:
            user = OAuthFilter.current_user()
            self.assertEqual("j.doe@example.com", user["edu_person_principal_name"])
