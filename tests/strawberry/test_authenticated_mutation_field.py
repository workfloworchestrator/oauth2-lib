from unittest import mock

from oauth2_lib.settings import oauth2lib_settings


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", False)
@mock.patch.object(oauth2lib_settings, "MUTATIONS_ENABLED", False)
def test_mutation_raises_error_when_oauth_and_mutations_are_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authenticated"


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", False)
@mock.patch.object(oauth2lib_settings, "MUTATIONS_ENABLED", True)
def test_mutation_raises_error_when_oauth_is_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authenticated"


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
@mock.patch.object(oauth2lib_settings, "MUTATIONS_ENABLED", False)
def test_mutation_raises_error_when_mutations_is_disabled(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authenticated"


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
@mock.patch.object(oauth2lib_settings, "MUTATIONS_ENABLED", True)
def test_mutation_raises_error_when_permission_is_denied(mock_graphql_app):
    test_client = mock_graphql_app(False)

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["errors"][0]["message"] == "User is not authorized to execute mutation `/addBook`"


@mock.patch.object(oauth2lib_settings, "OAUTH2_ACTIVE", True)
@mock.patch.object(oauth2lib_settings, "MUTATIONS_ENABLED", True)
def test_mutation_returns_data_when_permission_is_allowed(mock_graphql_app):
    test_client = mock_graphql_app()

    response = test_client.post(
        "/graphql",
        json={"query": 'mutation { addBook(title: "mutation title", author: "mutation author") { title, author } }'},
    )
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["data"] == {"addBook": {"title": "mutation title", "author": "mutation author"}}
