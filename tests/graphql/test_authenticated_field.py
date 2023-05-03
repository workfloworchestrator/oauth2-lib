import os
from unittest import mock


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "False"}, clear=True)
def test_query_returns_data_when_oauth_is_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post("/graphql", json={"query": "{ book { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {"book": {"title": "test title", "author": "test author"}}


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True"}, clear=True)
def test_query_raises_error_when_permission_is_denied(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post("/graphql", json={"query": "{ book { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authorized to query `/book/`"


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True"}, clear=True)
def test_query_returns_data_when_permission_is_allowed(mock_graphql_app):
    test_client = mock_graphql_app()

    response = test_client.post("/graphql", json={"query": "{ book { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {"book": {"title": "test title", "author": "test author"}}


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True"}, clear=True)
def test_query_with_nested_auth_raises_error_when_permission_is_denied(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post("/graphql", json={"query": "{ bookNestedAuth { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authorized to query `/booknestedauth/author/`"


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True"}, clear=True)
def test_query_with_nested_auth_returns_data_when_permission_is_allowed(mock_graphql_app):
    test_client = mock_graphql_app()

    response = test_client.post("/graphql", json={"query": "{ bookNestedAuth { title, author } }"})
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {"bookNestedAuth": {"title": "test title", "author": "test title author"}}
