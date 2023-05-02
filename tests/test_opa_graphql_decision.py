from typing import cast

import pytest
from fastapi import HTTPException

from oauth2_lib.fastapi import OIDCUser, opa_graphql_decision
from tests.test_fastapi import user_info_matching


@pytest.mark.asyncio
async def test_opa_graphql_decision_auto_error():
    def mock_user_info():
        return {}

    opa_decision_security = opa_graphql_decision("https://opa_url.test", cast(OIDCUser, mock_user_info), enabled=False)

    assert await opa_decision_security("", None) is None  # type:ignore


@pytest.mark.asyncio
async def test_opa_graphql_decision_user_not_allowed(make_mock_async_client):
    mock_async_client = make_mock_async_client({"result": False, "decision_id": "hoi"})
    opa_decision_security = opa_graphql_decision("https://opa_url.test", None)

    result = await opa_decision_security("/test/path", user_info_matching, mock_async_client)

    assert result is False
    opa_input = {
        "input": {
            **user_info_matching,
            "resource": "/test/path",
            "method": "POST",
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_graphql_decision_user_allowed(make_mock_async_client):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})
    opa_decision_security = opa_graphql_decision("https://opa_url.test", None)

    result = await opa_decision_security("/test/path", user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            **user_info_matching,
            "resource": "/test/path",
            "method": "POST",
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_graphql_decision_network_or_type_error(make_mock_async_client):
    mock_async_client = make_mock_async_client(error=TypeError())

    opa_decision_security = opa_graphql_decision("https://opa_url.test", None)

    with pytest.raises(HTTPException) as exception:
        await opa_decision_security("/test/path", user_info_matching, mock_async_client)

    assert exception.value.status_code == 503


@pytest.mark.asyncio
async def test_opa_graphql_decision_kwargs(make_mock_async_client):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})
    opa_decision_security = opa_graphql_decision("https://opa_url.test", None, opa_kwargs={"extra": 3})

    result = await opa_decision_security("/test/path", user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            "extra": 3,
            **user_info_matching,
            "resource": "/test/path",
            "method": "POST",
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_auto_error_not_allowed(make_mock_async_client):
    mock_async_client = make_mock_async_client({"result": False, "decision_id": "hoi"})
    opa_decision_security = opa_graphql_decision(
        "https://opa_url.test", None, opa_kwargs={"extra": 3}, auto_error=False
    )

    result = await opa_decision_security("/test/path", user_info_matching, mock_async_client)

    assert result is False
    opa_input = {
        "input": {
            "extra": 3,
            **user_info_matching,
            "resource": "/test/path",
            "method": "POST",
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_graphql_decision_auto_error_allowed(make_mock_async_client):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})
    opa_decision_security = opa_graphql_decision(
        "https://opa_url.test", None, opa_kwargs={"extra": 3}, auto_error=False
    )

    result = await opa_decision_security("/test/path", user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            "extra": 3,
            **user_info_matching,
            "resource": "/test/path",
            "method": "POST",
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)
