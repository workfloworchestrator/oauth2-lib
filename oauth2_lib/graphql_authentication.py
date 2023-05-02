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
import os
from typing import Any, Callable, Union

import strawberry
import structlog
from fastapi import HTTPException
from graphql.pyutils import Path
from strawberry import BasePermission
from strawberry.fastapi import BaseContext
from strawberry.types import Info
from strawberry.types.fields.resolver import StrawberryResolver
from strawberry.types.info import RootValueType

from oauth2_lib.fastapi import OIDCUserModel

logger = structlog.get_logger(__name__)


class OauthContext(BaseContext):
    def __init__(self, get_current_user: Callable[[], OIDCUserModel], get_opa_decision: Callable[[str], bool]):
        self.get_current_user = get_current_user
        self.get_opa_decision = get_opa_decision
        super().__init__()


OauthInfo = Info[OauthContext, RootValueType]


def get_path_as_string(path: Path) -> str:
    if path.prev:
        return f"{get_path_as_string(path.prev)}/{path.key}"
    else:
        return f"{path.key}"


class IsAuthenticated(BasePermission):
    message = "User is not authenticated"

    async def has_permission(self, source: Any, info: OauthInfo, **kwargs) -> bool:  # type: ignore
        if not os.environ.get("OAUTH2_ACTIVE"):
            return True

        service_name = f"/{os.environ.get('SERVICE_NAME') or ''}"
        path = f"{service_name}/{get_path_as_string(info.path)}/".lower()  # type: ignore

        context = info.context  # type: ignore
        try:
            logger.debug("Request headers", headers=info.context.request.headers)  # type: ignore
            current_user = await context.get_current_user(info.context.request)  # type: ignore
        except HTTPException:
            self.message = f"User is not authorized to query or has an invalid access token for path: `{path}`"
            return False

        opa_decision: bool = await context.get_opa_decision(path, current_user)

        logger.debug("Get opa decision", path=path, opa_decision=opa_decision)
        if not opa_decision:
            self.message = f"User is not authorized to query `{path}`"

        return opa_decision


class IsAuthenticatedForMutation(BasePermission):
    message = "User is not authenticated"

    async def has_permission(self, source: Any, info: OauthInfo, **kwargs) -> bool:  # type: ignore
        mutations_active = os.environ.get("OAUTH2_ACTIVE") and os.environ.get("MUTATIONS_ENABLED")
        env_ignore_mutation_disabled: list[str] = os.environ.get("ENVIRONMENT_IGNORE_MUTATION_DISABLED") or []  # type: ignore
        service_name = f"/{os.environ.get('SERVICE_NAME') or ''}"

        if not mutations_active:
            return os.environ.get("ENVIRONMENT") in env_ignore_mutation_disabled

        path = f"{service_name}/{info.path.key}"  # type: ignore
        try:
            current_user = await info.context.get_current_user(info.context.request)  # type: ignore
        except HTTPException:
            self.message = f"User is not authorized to query or has an invalid access token for path: `{path}`"
            return False
        opa_decision: bool = await info.context.get_opa_decision(path, current_user)  # type: ignore

        logger.debug("Get opa decision", path=path, opa_decision=opa_decision)
        if not opa_decision:
            self.message = f"User is not authorized to execute mutation `{path}`"

        return opa_decision


def authenticated_field(
    description: str,
    resolver: Union[StrawberryResolver, Callable, staticmethod, classmethod, None] = None,
    deprecation_reason: Union[str, None] = None,
) -> Any:
    return strawberry.field(
        description=description,
        resolver=resolver,
        deprecation_reason=deprecation_reason,
        permission_classes=[IsAuthenticated],
    )


def authenticated_federated_field(  # type: ignore
    description: str,
    resolver: Union[StrawberryResolver, Callable, staticmethod, classmethod, None] = None,
    deprecation_reason: Union[str, None] = None,
    requires: Union[list[str], None] = None,
    **kwargs,
) -> Any:
    return strawberry.federation.field(
        description=description,
        resolver=resolver,
        deprecation_reason=deprecation_reason,
        permission_classes=[IsAuthenticated],
        requires=requires,
        **kwargs,
    )
