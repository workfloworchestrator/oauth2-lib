# Copyright 2019-2023 SURF.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from collections.abc import Awaitable
from typing import Any, Callable, Union

import asyncstdlib
import strawberry
import structlog
from fastapi import HTTPException
from graphql.pyutils import Path
from starlette.requests import Request
from strawberry import BasePermission
from strawberry.fastapi import BaseContext
from strawberry.types import Info
from strawberry.types.fields.resolver import StrawberryResolver
from strawberry.types.info import RootValueType

from oauth2_lib.fastapi import OIDCUserModel
from oauth2_lib.settings import oauth2lib_settings

logger = structlog.get_logger(__name__)


class OauthContext(BaseContext):
    @asyncstdlib.cached_property
    async def get_current_user(self) -> Union[OIDCUserModel, None]:
        """Retrieve the OIDCUserModel once per graphql request.

        Note:
            This function should not raise exceptions, otherwise it will not be cached.
        """
        if not isinstance(self.request, Request):  # it could be None or a WebSocket
            logger.debug("Can't retrieve OIDCUserModel without a starlette Request", request_type=type(self.request))
            return None

        if not oauth2lib_settings.OAUTH2_ACTIVE:
            logger.debug("Not retrieving OIDCUserModel because OAUTH2_ACTIVE=False")
            return None

        try:
            return await self._get_current_user(self.request)
        except HTTPException as exc:
            logger.debug("User is not authenticated", status_code=exc.status_code, detail=exc.detail)
            return None

    def __init__(
        self,
        get_current_user: Callable[[Request], Awaitable[OIDCUserModel]],
        get_opa_decision: Callable[[str, OIDCUserModel], Awaitable[Union[bool, None]]],
    ):
        self._get_current_user = get_current_user
        self.get_opa_decision = get_opa_decision
        super().__init__()


OauthInfo = Info[OauthContext, RootValueType]


def get_path_as_string(path: Path) -> str:
    if path.prev:
        return f"{get_path_as_string(path.prev)}/{path.key}"
    return f"{path.key}"


def get_query_path(info: OauthInfo) -> str:
    service_name = oauth2lib_settings.SERVICE_NAME
    service_name_path = f"/{service_name}" if service_name else ""
    return f"{service_name_path}/{get_path_as_string(info.path)}/".lower()


def get_mutation_path(info: OauthInfo) -> str:
    service_name = oauth2lib_settings.SERVICE_NAME
    service_name_path = f"/{service_name}" if service_name else ""
    return f"{service_name_path}/{info.path.key}"


def skip_mutation_auth_checks() -> bool:
    is_exception = oauth2lib_settings.ENVIRONMENT in oauth2lib_settings.ENVIRONMENT_IGNORE_MUTATION_DISABLED
    logger.debug(
        "Mutations are disabled",
        OAUTH2_ACTIVE=oauth2lib_settings.OAUTH2_ACTIVE,
        OAUTH2_AUTHORIZATION_ACTIVE=oauth2lib_settings.OAUTH2_AUTHORIZATION_ACTIVE,
        MUTATIONS_ENABLED=oauth2lib_settings.MUTATIONS_ENABLED,
        is_exception=is_exception,
    )
    return is_exception


async def is_authenticated(info: OauthInfo) -> bool:
    """Check that the user has a valid and active authentication token."""
    current_user = await info.context.get_current_user
    return current_user is not None


async def is_authorized(info: OauthInfo, path: str) -> bool:
    """Check that the user is allowed to query/mutate this path."""
    context = info.context
    current_user = await context.get_current_user
    if not current_user:
        return False

    opa_decision = await context.get_opa_decision(path, current_user)
    authorized = bool(opa_decision)
    logger.debug("Received opa decision", path=path, opa_decision=opa_decision, is_authorized=authorized)

    return authorized


class IsAuthenticatedForQuery(BasePermission):
    message = "User is not authenticated"

    async def has_permission(self, source: Any, info: OauthInfo, **kwargs) -> bool:  # type: ignore
        if not oauth2lib_settings.OAUTH2_ACTIVE:
            logger.debug(
                "Authentication disabled",
                OAUTH2_ACTIVE=oauth2lib_settings.OAUTH2_ACTIVE,
                OAUTH2_AUTHORIZATION_ACTIVE=oauth2lib_settings.OAUTH2_AUTHORIZATION_ACTIVE,
            )
            return True

        return await is_authenticated(info)


class IsAuthenticatedForMutation(BasePermission):
    message = "User is not authenticated"

    async def has_permission(self, source: Any, info: OauthInfo, **kwargs) -> bool:  # type: ignore
        mutations_active = oauth2lib_settings.OAUTH2_ACTIVE and oauth2lib_settings.MUTATIONS_ENABLED
        if not mutations_active:
            return skip_mutation_auth_checks()

        return await is_authenticated(info)


class IsAuthorizedForQuery(BasePermission):
    async def has_permission(self, source: Any, info: OauthInfo, **kwargs) -> bool:  # type: ignore
        if not (oauth2lib_settings.OAUTH2_ACTIVE and oauth2lib_settings.OAUTH2_AUTHORIZATION_ACTIVE):
            logger.debug(
                "Authorization disabled",
                OAUTH2_ACTIVE=oauth2lib_settings.OAUTH2_ACTIVE,
                OAUTH2_AUTHORIZATION_ACTIVE=oauth2lib_settings.OAUTH2_AUTHORIZATION_ACTIVE,
            )
            return True

        path = get_query_path(info)
        if await is_authorized(info, path):
            return True

        self.message = f"User is not authorized to query `{path}`"
        return False


class IsAuthorizedForMutation(BasePermission):
    async def has_permission(self, source: Any, info: OauthInfo, **kwargs) -> bool:  # type: ignore
        mutations_active = (
            oauth2lib_settings.OAUTH2_ACTIVE
            and oauth2lib_settings.OAUTH2_AUTHORIZATION_ACTIVE
            and oauth2lib_settings.MUTATIONS_ENABLED
        )
        if not mutations_active:
            return skip_mutation_auth_checks()

        path = get_mutation_path(info)
        if await is_authorized(info, path):
            return True

        self.message = f"User is not authorized to execute mutation `{path}`"
        return False


def authenticated_field(
    description: str,
    resolver: Union[StrawberryResolver, Callable, staticmethod, classmethod, None] = None,
    deprecation_reason: Union[str, None] = None,
    permission_classes: Union[list[type[BasePermission]], None] = None,
) -> Any:
    permissions = permission_classes if permission_classes else []
    return strawberry.field(
        description=description,
        resolver=resolver,  # type: ignore
        deprecation_reason=deprecation_reason,
        permission_classes=[IsAuthenticatedForQuery, IsAuthorizedForQuery] + permissions,
    )


def authenticated_mutation_field(
    description: str,
    resolver: Union[StrawberryResolver, Callable, staticmethod, classmethod, None] = None,
    deprecation_reason: Union[str, None] = None,
    permission_classes: Union[list[type[BasePermission]], None] = None,
) -> Any:
    permissions = permission_classes if permission_classes else []
    return strawberry.field(
        description=description,
        resolver=resolver,  # type: ignore
        deprecation_reason=deprecation_reason,
        permission_classes=[IsAuthenticatedForMutation, IsAuthorizedForMutation] + permissions,
    )


def authenticated_federated_field(  # type: ignore
    description: str,
    resolver: Union[StrawberryResolver, Callable, staticmethod, classmethod, None] = None,
    deprecation_reason: Union[str, None] = None,
    requires: Union[list[str], None] = None,
    permission_classes: Union[list[type[BasePermission]], None] = None,
    **kwargs,
) -> Any:
    permissions = permission_classes if permission_classes else []
    return strawberry.federation.field(
        description=description,
        resolver=resolver,  # type: ignore
        deprecation_reason=deprecation_reason,
        permission_classes=[IsAuthenticatedForQuery, IsAuthorizedForQuery] + permissions,
        requires=requires,
        **kwargs,
    )
