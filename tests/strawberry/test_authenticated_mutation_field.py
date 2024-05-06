from unittest import mock

import pytest

from oauth2_lib.settings import oauth2lib_settings
from tests.conftest import MockResponse


@pytest.mark.parametrize(
    "oauth2_active, mutations_enabled, expected_error_message",
    [
        (False, False, "User is not authenticated"),
        (False, True, "User is not authenticated"),
        (True, False, "User is not authenticated"),
    ],
)
def test_mutation_errors_based_on_settings(
    mock_graphql_app, make_mock_async_client, discovery, oauth2_active, mutations_enabled, expected_error_message
):
    with (
        mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", oauth2_active),
        mock.patch.object(oauth2lib_settings, "MUTATIONS_ENABLED", mutations_enabled),
    ):
        test_client = mock_graphql_app()

        response = test_client.post(
            "/graphql",
            json={
                "query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'
            },
        )
        response_data = response.json()

        assert response.status_code == 200
        assert response_data["errors"][0]["message"] == expected_error_message


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
@mock.patch.object(oauth2lib_settings, "MUTATIONS_ENABLED", True)
def test_mutation_raises_error_when_permission_is_denied(mock_graphql_app, make_mock_async_client, discovery):
    mock_async_client = make_mock_async_client(
        [
            MockResponse(json=discovery),
            MockResponse(json={"result": False, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"}),
        ]
    )

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        test_client = mock_graphql_app()

        response = test_client.post(
            "/graphql",
            json={
                "query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'
            },
            headers={"Authorization": "Bearer example_token"},
        )
        response_data = response.json()

        assert response.status_code == 200
        assert response_data["errors"][0]["message"] == "User is not authorized to execute mutation `/addBook`"


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
@mock.patch.object(oauth2lib_settings, "MUTATIONS_ENABLED", True)
def test_mutation_returns_data_when_permission_is_allowed(mock_graphql_app, make_mock_async_client, discovery):
    mock_async_client = make_mock_async_client(
        [
            MockResponse(json=discovery),
            MockResponse(json={"result": True, "decision_id": "8ef9daf0-1a23-4a6b-8433-c64ef028bee8"}),
        ]
    )

    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        test_client = mock_graphql_app()

        response = test_client.post(
            "/graphql",
            json={
                "query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'
            },
            headers={"Authorization": "Bearer example_token"},
        )
        response_data = response.json()

        assert response.status_code == 200
        assert response_data["data"] == {"addBook": {"title": "mutation title", "author": "mutation author"}}
