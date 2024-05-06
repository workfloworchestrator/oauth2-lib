from unittest import mock

from oauth2_lib.settings import oauth2lib_settings
from tests.conftest import MockResponse


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", False)
def test_query_returns_data_when_oauth_is_disabled(mock_graphql_app):
    test_client = mock_graphql_app()

    response = test_client.post("/graphql", json={"query": "{ federatedBook { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {
        "federatedBook": {"title": "test title federated field", "author": "test author federated field"}
    }


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
def test_query_raises_error_when_permission_is_denied(mock_graphql_app, make_mock_async_client, discovery):
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
            json={"query": "{ federatedBook { title, author } }"},
            headers={"Authorization": "Bearer example_token"},
        )
        response_data = response.json()

        assert response.status_code == 200
        assert response_data["errors"][0]["message"] == "User is not authorized to query `/federatedbook/`"


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
def test_query_returns_data_when_permission_is_allowed(mock_graphql_app, make_mock_async_client, discovery):
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
            json={"query": "{ federatedBook { title, author } }"},
            headers={"Authorization": "Bearer example_token"},
        )
        response_data = response.json()

        assert response.status_code == 200
        assert response_data["data"] == {
            "federatedBook": {"title": "test title federated field", "author": "test author federated field"}
        }
