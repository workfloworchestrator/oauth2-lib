from typing import Optional

import pytest
import strawberry
from fastapi import Depends, FastAPI
from starlette.requests import Request
from starlette.testclient import TestClient
from strawberry.fastapi import GraphQLRouter

from oauth2_lib.fastapi import GraphQLOPAAuthorization, OIDCAuth, OIDCUserModel
from oauth2_lib.strawberry import (
    OauthContext,
    authenticated_federated_field,
    authenticated_field,
    authenticated_mutation_field,
)
from tests.test_fastapi import user_info_matching


@pytest.fixture
def mock_graphql_app():  # noqa: C901
    def _mock_graphql_app():
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
            class OIDCAuthMock(OIDCAuth):
                async def userinfo(self, request: Request, token: Optional[str] = None) -> Optional[OIDCUserModel]:
                    return user_info_matching

            oidc_auth = OIDCAuthMock(
                "openid_url", "openid_url/.well-known/openid-configuration", "id", "secret", OIDCUserModel
            )

            return oidc_auth.authenticate

        async def get_opa_security_graphql():
            return GraphQLOPAAuthorization(opa_url="https://opa_url.test").authorize

        async def get_context(
            get_current_user=Depends(get_oidc_user),  # noqa: B008
            get_authorization_decision=Depends(get_opa_security_graphql),  # noqa: B008
        ) -> OauthContext:  # type: ignore # noqa: B008
            return OauthContext(
                get_current_user=get_current_user, get_authorization_decision=get_authorization_decision
            )

        app = FastAPI()
        schema = strawberry.Schema(query=Query, mutation=Mutation)
        graphql_app = GraphQLRouter(schema, context_getter=get_context)
        app.include_router(graphql_app, prefix="/graphql")

        return TestClient(app)

    return _mock_graphql_app
