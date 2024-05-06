from http import HTTPStatus
from typing import cast
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from oauth2_lib.fastapi import GraphQLOPAAuthorization, OIDCUserModel
from oauth2_lib.settings import oauth2lib_settings
from tests.conftest import MockResponse
from tests.test_fastapi import user_info_matching


@pytest.mark.asyncio
async def test_opa_graphql_decision_auto_error():
    oauth2lib_settings.OAUTH2_ACTIVE = False
    authorization = GraphQLOPAAuthorization(opa_url="https://opa_url.test")
    assert await authorization.authorize("", cast(OIDCUserModel, {})) is None
    oauth2lib_settings.OAUTH2_ACTIVE = True


@pytest.mark.asyncio
async def test_opa_graphql_decision_user_not_allowed_autoerror_true(make_mock_async_client):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": False, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = GraphQLOPAAuthorization(opa_url="https://opa_url.test", auto_error=True)
        with pytest.raises(HTTPException) as exception_info:
            await authorization.authorize("/test/path", user_info=user_info_matching)

        assert exception_info.value.status_code == HTTPStatus.FORBIDDEN
        expected_detail = f"User is not allowed to access resource: /test/path Decision was taken with id: {'8ef9daf0-1a23-4a6b-8433-c64ef028bee8'}"
        assert exception_info.value.detail == expected_detail

        opa_input = {"input": {**user_info_matching, "resource": "/test/path", "method": "POST"}}
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_graphql_decision_user_not_allowed_autoerror_false(make_mock_async_client):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": False, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = GraphQLOPAAuthorization(opa_url="https://opa_url.test", auto_error=False)
        result = await authorization.authorize("/test/path", user_info_matching)

        assert result is False
        opa_input = {
            "input": {
                **user_info_matching,
                "resource": "/test/path",
                "method": "POST",
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_graphql_decision_user_allowed(make_mock_async_client):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": True, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = GraphQLOPAAuthorization(opa_url="https://opa_url.test", auto_error=False)
        result = await authorization.authorize("/test/path", user_info_matching)

        assert result is True
        opa_input = {
            "input": {
                **user_info_matching,
                "resource": "/test/path",
                "method": "POST",
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_graphql_decision_network_or_type_error(make_mock_async_client):
    mock_async_client = make_mock_async_client(MockResponse(error=TypeError()))

    with patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = GraphQLOPAAuthorization(opa_url="https://opa_url.test")

        with pytest.raises(HTTPException) as exception:
            await authorization.authorize("/test/path", user_info_matching)

        assert exception.value.status_code == 503
        assert exception.value.detail == "Policy agent is unavailable"


@pytest.mark.asyncio
async def test_opa_graphql_decision_kwargs(make_mock_async_client):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": True, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = GraphQLOPAAuthorization(
            opa_url="https://opa_url.test", auto_error=False, opa_kwargs={"extra": 3}
        )

        result = await authorization.authorize("/test/path", user_info_matching)

        assert result is True

        opa_input = {
            "input": {
                "extra": 3,
                **user_info_matching,
                "resource": "/test/path",
                "method": "POST",
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_auto_error_not_allowed(make_mock_async_client):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": False, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = GraphQLOPAAuthorization(
            opa_url="https://opa_url.test", opa_kwargs={"extra": 3}, auto_error=False
        )

        result = await authorization.authorize("/test/path", user_info_matching)

        assert result is False
        opa_input = {
            "input": {
                "extra": 3,
                **user_info_matching,
                "resource": "/test/path",
                "method": "POST",
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_graphql_decision_auto_error_allowed(make_mock_async_client):
    mock_async_client = make_mock_async_client(
        MockResponse(json={"result": True, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"})
    )

    with patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        authorization = GraphQLOPAAuthorization(
            opa_url="https://opa_url.test", opa_kwargs={"extra": 3}, auto_error=False
        )

        result = await authorization.authorize("/test/path", user_info_matching)

        assert result is True
        opa_input = {
            "input": {
                "extra": 3,
                **user_info_matching,
                "resource": "/test/path",
                "method": "POST",
            }
        }
        mock_async_client.client.post.assert_called_with("https://opa_url.test", json=opa_input)
