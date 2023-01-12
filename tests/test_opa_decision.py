from typing import cast
from unittest import mock

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.websockets import WebSocket

from oauth2_lib.fastapi import OIDCUser, opa_decision
from tests.test_fastapi import user_info_matching


@pytest.mark.asyncio
async def test_opa_decision_auto_error():
    def mock_user_info():
        return {}

    opa_decision_security = opa_decision("https://opa_url.test", cast(OIDCUser, mock_user_info), enabled=False)

    mock_request = mock.MagicMock(spec=Request)

    assert await opa_decision_security(mock_request, {}, None) is None  # type:ignore


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
async def test_opa_decision_user_not_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": False, "decision_id": "hoi"})

    opa_decision_security = opa_decision("https://opa_url.test", None)  # type:ignore

    with pytest.raises(HTTPException) as exception:
        await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert exception.value.status_code == 403
    opa_input = {
        "input": {
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_network_or_type_error(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client(error=TypeError())

    opa_decision_security = opa_decision("https://opa_url.test", None)  # type:ignore

    with pytest.raises(HTTPException) as exception:
        await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert exception.value.status_code == 503


@pytest.mark.asyncio
async def test_opa_decision_user_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})

    opa_decision_security = opa_decision("https://opa_url.test", None)  # type:ignore

    result = await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_user_allowed_websocket_request(make_mock_async_client, mock_websocket_request):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})

    opa_decision_security = opa_decision("https://opa_url.test", None)  # type:ignore

    result = await opa_decision_security(mock_websocket_request, user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_kwargs(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})

    opa_decision_security = opa_decision("https://opa_url.test", None, opa_kwargs={"extra": 3})  # type:ignore

    result = await opa_decision_security(mock_request, user_info_matching, mock_async_client)

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
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_auto_error_not_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": False, "decision_id": "hoi"})

    opa_decision_security = opa_decision(
        "https://opa_url.test", None, opa_kwargs={"extra": 3}, auto_error=False  # type:ignore
    )

    result = await opa_decision_security(mock_request, user_info_matching, mock_async_client)

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
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_auto_error_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})

    opa_decision_security = opa_decision(
        "https://opa_url.test", None, opa_kwargs={"extra": 3}, auto_error=False  # type:ignore
    )
    result = await opa_decision_security(mock_request, user_info_matching, mock_async_client)

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
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


# @pytest.mark.asyncio
# async def test_opa_decision_opa_unavailable(make_mock_async_client, mock_request):
#     mock_async_client = make_mock_async_client({"result": False, "decision_id": "hoi"})

#     opa_decision_security = opa_decision("https://opa_url.test", None)

#     with pytest.raises(HTTPException) as exception:
#         await opa_decision_security(mock_request, user_info_matching, mock_async_client)
#     assert exception.value.status_code == 503
