import os
from unittest import mock


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "False", "MUTATIONS_ENABLED": "False"}, clear=True)
def test_mutation_raises_error_when_oauth_and_mutations_are_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authenticated"


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "False", "MUTATIONS_ENABLED": "True"}, clear=True)
def test_mutation_raises_error_when_oauth_is_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authenticated"


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True", "MUTATIONS_ENABLED": "False"}, clear=True)
def test_mutation_raises_error_when_mutations_is_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authenticated"


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True", "MUTATIONS_ENABLED": "True"}, clear=True)
def test_mutation_raises_error_when_permission_is_denied(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authorized to execute mutation `/addBook`"


@mock.patch.dict(os.environ, {"OAUTH2_ACTIVE": "True", "MUTATIONS_ENABLED": "True"}, clear=True)
def test_mutation_returns_data_when_permission_is_allowed(mock_graphql_app):
    test_client = mock_graphql_app()

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {"addBook": {"title": "mutation title", "author": "mutation author"}}
