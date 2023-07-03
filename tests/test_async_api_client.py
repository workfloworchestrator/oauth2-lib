import json
from http import HTTPStatus
from unittest import mock

import pytest
import urllib3
from urllib3_mock import Responses

from oauth2_lib.async_api_client import AsyncAuthMixin

EXPIRED_TOKEN = "expired token"  # noqa: S105

VALID_TOKEN = "valid token"  # noqa: S105

BASE_URL = "http://my-api"


class ApiException(Exception):
    # Copy of OpenAPI's ApiException class

    def __init__(self, status=None, reason=None, http_resp=None):
        if http_resp:
            self.status = http_resp.status
            self.reason = http_resp.reason
            self.body = http_resp.data
            self.headers = http_resp.headers
        else:
            self.status = status
            self.reason = reason
            self.body = None
            self.headers = None

    def __str__(self):
        error_message = "({})\n" "Reason: {}\n".format(self.status, self.reason)
        if self.headers:
            error_message += f"HTTP response headers: {self.headers}\n"

        if self.body:
            error_message += f"HTTP response body: {self.body}\n"

        return error_message


def make_api_client(url=BASE_URL, token=VALID_TOKEN):
    """Create an api client similar to these.

    > ims_api_client = ImsApiClient(
    >     oauth_client=oauth_client_credentials,
    >     oauth_client_name="<hidden>",
    >     oauth_active=oauth2_settings.OAUTH2_ACTIVE_REQUESTS,
    >     host=external_service_settings.IMS_URI,
    > )
    """

    class FakeApiClient:
        # Simplified OpenApi Client
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, url, query_params, headers, *args):
            http = urllib3.PoolManager()
            response = http.request(method, url, headers=headers)
            if not 200 <= response.status <= 299:
                raise ApiException(http_resp=response)
            return response

    class FakeFinalApiClient(AsyncAuthMixin, FakeApiClient):
        # Simplified client implementation of the OpenApi Client
        def __init__(self, host, *args, **kwargs):
            config = mock.MagicMock()
            config.host = host
            config.access_token = None
            config.access_token = None

            async def mock_fetch_access_token():
                return {"access_token": VALID_TOKEN}

            base_oauth_client = mock.MagicMock()
            oauth_client = mock.MagicMock()
            oauth_client.fetch_access_token = mock_fetch_access_token
            base_oauth_client.actualclient = oauth_client
            super().__init__(
                oauth_client=base_oauth_client,
                oauth_client_name="actualclient",
                oauth_active=True,
                configuration=config,
            )

            self._token = {"access_token": token}

    return FakeFinalApiClient(url)


class ApiMock:
    def __init__(self, responses: Responses):
        self.responses = responses

    def get_endpoint(self):
        def verify_token(request):
            if request.headers["Authorization"] == f"bearer {VALID_TOKEN}":
                return HTTPStatus.OK, {}, json.dumps({"data": "hello"})

            if request.headers["Authorization"] == f"bearer {EXPIRED_TOKEN}":
                return HTTPStatus.UNAUTHORIZED, {}, json.dumps({"error": "unauthorized"})

            unrecognized_token = request.headers["Authorization"]
            raise AssertionError(f"Invalid access token {unrecognized_token}")

        self.responses.add_callback("GET", "/app/endpoint", callback=verify_token, content_type="application/json")

    def get_endpoint_500(self):
        self.responses.add(
            "GET",
            "/app/endpoint",
            body=json.dumps({"error": "unknown"}),
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            content_type="application/json",
        )

    def get_endpoint_404(self):
        self.responses.add(
            "GET",
            "/app/endpoint",
            body=json.dumps({"error": "not found"}),
            status=HTTPStatus.NOT_FOUND,
            content_type="application/json",
        )


def test_asyncauthmixin_request_200(responses):
    """Test that making a request with valid token works."""

    # given
    client = make_api_client()

    apimock = ApiMock(responses)
    apimock.get_endpoint()

    # when
    res = client.request("GET", f"{BASE_URL}/app/endpoint")

    # then
    assert res.status == HTTPStatus.OK
    assert len(responses.calls) == 1


def test_asyncauthmixin_request_401_then_200(responses):
    """Test that a request with expired token is retried with a valid token."""
    # given
    client = make_api_client(token=EXPIRED_TOKEN)
    apimock = ApiMock(responses)
    apimock.get_endpoint()

    # when
    res = client.request("GET", f"{BASE_URL}/app/endpoint")

    # then
    assert res.status == HTTPStatus.OK
    assert len(responses.calls) == 2


def test_asyncauthmixin_request_500(responses):
    # given
    client = make_api_client(token=EXPIRED_TOKEN)
    apimock = ApiMock(responses)
    apimock.get_endpoint_500()

    # when
    with pytest.raises(ApiException) as exc:
        client.request("GET", f"{BASE_URL}/app/endpoint")

    # then
    assert exc.value.status == HTTPStatus.INTERNAL_SERVER_ERROR
    assert len(responses.calls) == 1


def test_asyncauthmixin_request_404(responses):
    # given
    client = make_api_client(token=EXPIRED_TOKEN)
    apimock = ApiMock(responses)
    apimock.get_endpoint_404()

    # when
    with pytest.raises(ApiException) as exc:
        client.request("GET", f"{BASE_URL}/app/endpoint")

    # then
    assert exc.value.status == HTTPStatus.NOT_FOUND
    assert len(responses.calls) == 1
