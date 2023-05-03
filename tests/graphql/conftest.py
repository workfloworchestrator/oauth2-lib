import pytest
import strawberry
from fastapi import Depends, FastAPI
from starlette.testclient import TestClient
from strawberry.fastapi import GraphQLRouter

from oauth2_lib.fastapi import opa_graphql_decision
from oauth2_lib.graphql_authentication import (
    OauthContext,
    authenticated_federated_field,
    authenticated_field,
    authenticated_mutation_field,
)
from tests.test_fastapi import user_info_matching


@pytest.fixture
def mock_graphql_app(make_mock_async_client):
    def _mock_graphql_app(authorized=True):
        mock_async_client = make_mock_async_client({"result": authorized, "decision_id": "hoi"})

        @strawberry.type
        class BookType:
            title: str
            author: str

        @strawberry.type
        class bookNestedAuthType:
            title: str

            @authenticated_field("test authentication for book author")
            def author(self) -> str:
                return f"{self.title} author"

        @strawberry.type
        class Query:
            @authenticated_field("query book test")
            def book(self) -> BookType:
                return BookType(title="test title", author="test author")

            @strawberry.field(description="query book nested auth test")
            def book_nested_auth(self) -> bookNestedAuthType:
                return bookNestedAuthType(title="test title")

            @authenticated_federated_field("federated field book test")
            def federated_book(self) -> BookType:
                return BookType(title="test title federated field", author="test author federated field")

        @strawberry.type
        class Mutation:
            @authenticated_mutation_field("mutation test")
            def add_book(self, title: str, author: str) -> BookType:
                return BookType(title=title, author=author)

        async def get_oidc_user():
            async def get_current_user(request=None):
                return user_info_matching

            return get_current_user

        async def get_opa_security_graphql():
            return opa_graphql_decision("https://opa_url.test", None, async_request=mock_async_client)

        async def get_context(
            get_current_user=Depends(get_oidc_user),  # noqa: B008
            get_opa_decision=Depends(get_opa_security_graphql),  # noqa: B008
        ) -> OauthContext:  # type: ignore # noqa: B008
            return OauthContext(get_current_user=get_current_user, get_opa_decision=get_opa_decision)

        app = FastAPI()
        schema = strawberry.Schema(query=Query, mutation=Mutation)
        graphql_app = GraphQLRouter(schema, context_getter=get_context)
        app.include_router(graphql_app, prefix="/graphql")

        return TestClient(app)

    return _mock_graphql_app
