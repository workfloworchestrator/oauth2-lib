from unittest import mock

from oauth2_lib.settings import oauth2lib_settings


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", False)
def test_query_returns_data_when_oauth_is_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post("/graphql", json={"query": "{ federatedBook { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {
        "federatedBook": {"title": "test title federated field", "author": "test author federated field"}
    }


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
def test_query_raises_error_when_permission_is_denied(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post("/graphql", json={"query": "{ federatedBook { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authorized to query `/federatedbook/`"


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
def test_query_returns_data_when_permission_is_allowed(mock_graphql_app):
    test_client = mock_graphql_app()

    response = test_client.post("/graphql", json={"query": "{ federatedBook { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {
        "federatedBook": {"title": "test title federated field", "author": "test author federated field"}
    }
