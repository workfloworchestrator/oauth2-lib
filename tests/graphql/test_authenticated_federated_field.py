import os
from unittest import mock


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "False"}, clear=True)
def test_query_returns_data_when_oauth_is_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post("/graphql", json={"query": "{ federatedBook { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {
        "federatedBook": {"title": "test title federated field", "author": "test author federated field"}
    }


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True"}, clear=True)
def test_query_raises_error_when_permission_is_denied(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post("/graphql", json={"query": "{ federatedBook { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authorized to query `/federatedbook/`"


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True"}, clear=True)
def test_query_returns_data_when_permission_is_allowed(mock_graphql_app):
    test_client = mock_graphql_app()

    response = test_client.post("/graphql", json={"query": "{ federatedBook { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {
        "federatedBook": {"title": "test title federated field", "author": "test author federated field"}
    }
