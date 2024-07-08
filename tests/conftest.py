from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient, Response
from urllib3_mock import Responses


class MockResponse:
    def __init__(self, json: Any | None = None, status_code: int = 200, error: Exception | None = None):
        self.json = json
        self.status_code = status_code
        self.error = error


class AsyncClientMock:
    def __init__(self, client):
        self.client = client

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture(scope="session")
def make_mock_async_client():
    """Creates a mocked httpx.AsyncClient.

    Parameters:
    - mock_response: MockResponse | List[MockResponse] | None. Defines mock HTTP responses.

    Returns:
    - A mocked httpx.AsyncClient instance for testing HTTP requests.

    Usage:
    Pass a MockResponse for single or list for multiple sequential HTTP responses.
    """

    def _make_mock_async_client(mock_response: MockResponse | list[MockResponse] | None = None):
        mock_async_client = AsyncMock(spec=AsyncClient)

        mock_responses = ([mock_response] if isinstance(mock_response, MockResponse) else mock_response) or []

        async def async_side_effect(*args, **kwargs):
            for index, response in enumerate(mock_responses):
                if response.error:
                    raise response.error

                mock_http_response = MagicMock(spec=Response)
                mock_http_response.json.return_value = response.json
                mock_http_response.status_code = response.status_code
                mock_responses.pop(index)
                return mock_http_response

            return MagicMock(spec=Response, json=lambda: {}, status_code=200)

        mock_async_client.get.side_effect = async_side_effect
        mock_async_client.post.side_effect = async_side_effect

        return AsyncClientMock(mock_async_client)

    return _make_mock_async_client


@pytest.fixture(autouse=False)
def responses():
    responses_mock = Responses("requests.packages.urllib3")

    def _find_request(call):
        if not (mock_url := responses_mock._find_match(call.request)):
            raise Exception(f"Call not mocked: {call.request}")
        return mock_url

    def _to_tuple(url_mock):
        return (url_mock["url"], url_mock["method"], url_mock["match_querystring"])

    with responses_mock:
        yield responses_mock

        mocked_urls = map(_to_tuple, responses_mock._urls)
        used_urls = map(_to_tuple, map(_find_request, responses_mock.calls))
        if not_used := set(mocked_urls) - set(used_urls):
            pytest.fail(f"Found unused responses mocks: {not_used}", pytrace=False)


@pytest.fixture(scope="session")
def discovery():
    return {
        "issuer": "https://connect.test.surfconext.nl",
        "authorization_endpoint": "https://connect.test.surfconext.nl/oidc/authorize",
        "token_endpoint": "https://connect.test.surfconext.nl/oidc/token",
        "userinfo_endpoint": "https://connect.test.surfconext.nl/oidc/userinfo",
        "introspect_endpoint": "https://connect.test.surfconext.nl/oidc/introspect",
        "jwks_uri": "https://connect.test.surfconext.nl/oidc/certs",
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token",
        ],
        "response_modes_supported": ["fragment", "query", "form_post"],
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "groups", "profile", "email", "address", "phone"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": [
            "aud",
            "nbf",
            "iss",
            "exp",
            "iat",
            "jti",
            "nonce",
            "at_hash",
            "c_hash",
            "s_hash",
            "at_hash",
            "auth_time",
            "sub",
            "edumember_is_member_of",
            "eduperson_affiliation",
            "eduperson_entitlement",
            "eduperson_principal_name",
            "eduperson_scoped_affiliation",
            "email",
            "email_verified",
            "family_name",
            "given_name",
            "name",
            "nickname",
            "preferred_username",
            "schac_home_organization",
            "schac_home_organization_type",
            "schac_personal_unique_code",
            "eduperson_orcid",
            "eckid",
            "surf-crm-id",
            "uids",
        ],
        "claims_parameter_supported": True,
        "request_parameter_supported": True,
        "code_challenge_methods_supported": ["plain", "S256"],
    }
