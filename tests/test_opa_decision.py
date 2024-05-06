from typing import cast
from unittest import mock

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.websockets import WebSocket

from oauth2_lib.fastapi import OIDCUserModel, OPAAuthorization
from oauth2_lib.settings import oauth2lib_settings
from tests.conftest import MockResponse
from tests.test_fastapi import user_info_matching


@pytest.fixture
def mock_request():
    mock_request = mock.MagicMock(spec=Request)
    mock_request.url.path = "/test/path"
    mock_request.method = "GET"
    mock_request.path_params = {}
    mock_request.json.return_value = {}
    return mock_request


@pytest.fixture
def mock_websocket_request():
    mock_request = mock.MagicMock(spec=WebSocket)
    mock_request.url.path = "/test/path"
    mock_request.path_params = {}
    return mock_request


@pytest.mark.asyncio
async def test_opa_decision_auto_error(mock_request):
    oauth2lib_settings.OAUTH2_ACTIVE = False
    authorization = OPAAuthorization("https://opa_url.test")
    assert await authorization.authorize(mock_request, cast(OIDCUserModel, {})) is None
    oauth2lib_settings.OAUTH2_ACTIVE = True


@pytest.mark.asyncio
async def test_opa_decision_user_not_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": False, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = OPAAuthorization(opa_url="https://opa_url.test")

        with pytest.raises(HTTPException) as exception:
            await authorization.authorize(mock_request, user_info_matching)

        assert exception.value.status_code == 403
        assert (
            exception.value.detail
            == f"User is not allowed to access resource: /test/path Decision was taken with id: {'8ef9daf0-1a23-4a6b-8433-c64ef028bee8'}"
        )

        opa_input = {
            "input": {
                **user_info_matching,
                "resource": "/test/path",
                "method": "GET",
                "arguments": {"path": {}, "query": {}, "json": {}},
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_network_or_type_error(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client(MockResponse(error=TypeError()))

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = OPAAuthorization(opa_url="https://opa_url.test")

        with pytest.raises(HTTPException) as exception:
            await authorization.authorize(mock_request, user_info_matching)

        assert exception.value.status_code == 503
        assert exception.value.detail == "Policy agent is unavailable"


@pytest.mark.asyncio
async def test_opa_decision_user_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": True, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = OPAAuthorization(opa_url="https://opa_url.test")
        result = await authorization.authorize(mock_request, user_info_matching)

        assert result is True
        opa_input = {
            "input": {
                **user_info_matching,
                "resource": "/test/path",
                "method": "GET",
                "arguments": {"path": {}, "query": {}, "json": {}},
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_user_allowed_websocket_request(make_mock_async_client, mock_websocket_request):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": True, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = OPAAuthorization(opa_url="https://opa_url.test")
        result = await authorization.authorize(mock_websocket_request, user_info_matching)

        assert result is True
        opa_input = {
            "input": {
                **user_info_matching,
                "resource": "/test/path",
                "method": "GET",
                "arguments": {"path": {}, "query": {}, "json": {}},
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_kwargs(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": True, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = OPAAuthorization(opa_url="https://opa_url.test", opa_kwargs={"extra": 3})
        result = await authorization.authorize(mock_request, user_info_matching)

        assert result is True
        opa_input = {
            "input": {
                "extra": 3,
                **user_info_matching,
                "resource": "/test/path",
                "method": "GET",
                "arguments": {"path": {}, "query": {}, "json": {}},
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_auto_error_not_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": False, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = OPAAuthorization(opa_url="https://opa_url.test", opa_kwargs={"extra": 3}, auto_error=False)
        result = await authorization.authorize(mock_request, user_info_matching)

        assert result is False
        opa_input = {
            "input": {
                "extra": 3,
                **user_info_matching,
                "resource": "/test/path",
                "method": "GET",
                "arguments": {"path": {}, "query": {}, "json": {}},
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_auto_error_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": True, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = OPAAuthorization(opa_url="https://opa_url.test", opa_kwargs={"extra": 3}, auto_error=False)
        result = await authorization.authorize(mock_request, user_info_matching)

        assert result is True
        opa_input = {
            "input": {
                "extra": 3,
                **user_info_matching,
                "resource": "/test/path",
                "method": "GET",
                "arguments": {"path": {}, "query": {}, "json": {}},
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


# @pytest.mark.asyncio
# async def test_opa_decision_opa_unavailable(make_mock_async_client, mock_request):
#     mock_async_client = make_mock_async_client({"result": False, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})

#     opa_decision_security = opa_decision("https://opa_url.test", None)

#     with pytest.raises(HTTPException) as exception:
#         await opa_decision_security(mock_request, user_info_matching, mock_async_client)
#     assert exception.value.status_code == 503
