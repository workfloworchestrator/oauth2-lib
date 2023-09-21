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
import re
import ssl
from collections.abc import AsyncGenerator, Awaitable, Mapping
from http import HTTPStatus
from json import JSONDecodeError
from typing import Any, Callable, Optional, Union, cast

from fastapi.exceptions import HTTPException
from fastapi.param_functions import Depends
from fastapi.requests import Request
from fastapi.security.http import HTTPBearer
from httpx import AsyncClient, BasicAuth, NetworkError
from pydantic import BaseModel
from starlette.requests import ClientDisconnect
from structlog import get_logger

from oauth2_lib.settings import oauth2lib_settings

logger = get_logger(__name__)

HTTPX_SSL_CONTEXT = ssl.create_default_context()  # https://github.com/encode/httpx/issues/838


class OIDCUserModel(dict):
    """The standard claims of a OIDCUserModel object. Defined per `Section 5.1`_.

    .. _`Section 5.1`: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    """

    #: registered claims that OIDCUserModel supports
    REGISTERED_CLAIMS = [
        "sub",
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "email",
        "email_verified",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "phone_number",
        "phone_number_verified",
        "address",
        "updated_at",
    ]

    def __getattr__(self, key: str) -> Any:
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTERED_CLAIMS:
                return self.get(key)
            raise error

    """
    Below this line are SURFnet specific properties that are used often in code to either display or check on.
    """

    @property
    def user_name(self) -> str:
        if "user_name" in self.keys():
            return cast(str, self["user_name"])
        if "unspecified_id" in self.keys():
            return cast(str, self["unspecified_id"])
        return ""

    @property
    def display_name(self) -> str:
        return self.get("display_name", "")

    @property
    def principal_name(self) -> str:
        return self.get("eduperson_principal_name", "")

    @property
    def memberships(self) -> list[str]:
        return self.get("edumember_is_member_of", [])

    @property
    def teams(self) -> set[str]:
        prefix = "urn:collab:group:surfteams.nl:nl:surfnet:diensten:"
        length = len(prefix)
        return {urn[length:] for urn in self.memberships if urn.startswith(prefix)}

    @property
    def entitlements(self) -> list[str]:
        return self.get("eduperson_entitlement", [])

    @property
    def roles(self) -> set[str]:
        prefix = "urn:mace:surfnet.nl:surfnet.nl:sab:role:"
        length = len(prefix)
        return {urn[length:] for urn in self.entitlements if urn.startswith(prefix)}

    @property
    def organization_codes(self) -> set[str]:
        prefix = "urn:mace:surfnet.nl:surfnet.nl:sab:organizationCode:"
        length = len(prefix)
        return {urn[length:] for urn in self.entitlements if urn.startswith(prefix)}

    @property
    def organization_guids(self) -> set[str]:
        prefix = "urn:mace:surfnet.nl:surfnet.nl:sab:organizationGUID:"
        length = len(prefix)
        return {urn[length:] for urn in self.entitlements if urn.startswith(prefix)}

    @property
    def scopes(self) -> set[str]:
        if isinstance(self.get("scope"), list):
            return set(self.get("scope"))  # type: ignore
        return set(re.split("[ ,]", self.get("scope", "")))

    @property
    def is_resource_server(self) -> bool:
        return self.get("is_resource_server", False)

    @property
    def surf_crm_id(self) -> str:
        return self.get("surf-crm-id", "")


async def _make_async_client() -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(http1=True, verify=HTTPX_SSL_CONTEXT) as client:
        yield client


class OIDCConfig(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    introspect_endpoint: Optional[str]
    introspection_endpoint: Optional[str]
    jwks_uri: str
    response_types_supported: list[str]
    response_modes_supported: list[str]
    grant_types_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    scopes_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    claims_supported: list[str]
    claims_parameter_supported: bool
    request_parameter_supported: bool
    code_challenge_methods_supported: list[str]


class OPAResult(BaseModel):
    result: bool = False
    decision_id: str


class OIDCUser(HTTPBearer):
    """OIDCUser class extends the HTTPBearer class to do extra verification.

    The class will act as follows:
        1. Validate the Credentials at SURFconext by calling the UserInfo endpoint
        2. When receiving an active token it will enrich the response through the database roles
    """

    openid_config: Union[OIDCConfig, None] = None
    openid_url: str
    resource_server_id: str
    resource_server_secret: str

    def __init__(
        self,
        openid_url: str,
        resource_server_id: str,
        resource_server_secret: str,
        auto_error: bool = True,
        scheme_name: Union[str, None] = None,
    ):
        super().__init__(auto_error=auto_error)
        self.openid_url = openid_url
        self.resource_server_id = resource_server_id
        self.resource_server_secret = resource_server_secret
        self.scheme_name = scheme_name or self.__class__.__name__

    async def __call__(self, request: Request, token: Union[str, None] = None) -> Union[OIDCUserModel, None]:  # type: ignore
        """Return the OIDC user from OIDC introspect endpoint.

        This is used as a security module in Fastapi projects

        Args:
            request: Starlette request method.
            token: Optional value to directly pass a token.

        Returns:
            OIDCUserModel object.

        """
        if not oauth2lib_settings.OAUTH2_ACTIVE:
            return None

        async with AsyncClient(http1=True, verify=HTTPX_SSL_CONTEXT) as async_request:
            await self.check_openid_config(async_request)

            if not token:
                credentials = await super().__call__(request)
                if not credentials:
                    return None
                token = credentials.credentials

            user_info = await self.introspect_token(async_request, token)

            if "active" not in user_info:
                logger.error("Token doesn't have the mandatory 'active' key, probably caused by a caching problem")
                raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Missing active key")
            if not user_info.get("active", False):
                logger.info("User is not active", url=request.url, user_info=user_info)
                raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="User is not active")

            logger.debug("OIDCUserModel object.", user_info=user_info)
            return user_info

    async def check_openid_config(self, async_request: AsyncClient) -> None:
        """Check of openid config is loaded and load if not."""
        if self.openid_config is not None:
            return

        response = await async_request.get(self.openid_url + "/.well-known/openid-configuration")
        self.openid_config = OIDCConfig.parse_obj(response.json())

    async def introspect_token(self, async_request: AsyncClient, token: str) -> OIDCUserModel:
        """Introspect the access token to retrieve the user info.

        Args:
            async_request: The async request
            token: the access_token

        Returns:
            OIDCUserModel from openid server

        """
        await self.check_openid_config(async_request)
        assert self.openid_config

        endpoint = self.openid_config.introspect_endpoint or self.openid_config.introspection_endpoint or ""
        response = await async_request.post(
            endpoint,
            params={"token": token},
            data={"token": token},
            auth=BasicAuth(self.resource_server_id, self.resource_server_secret),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        try:
            data = dict(response.json())
        except JSONDecodeError:
            logger.debug(
                "Unable to parse introspect response",
                detail=response.text,
                resource_server_id=self.resource_server_id,
                openid_url=self.openid_url,
            )
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail=response.text)
        logger.debug("Response from openid introspect", response=data)

        if response.status_code not in range(200, 300):
            logger.debug(
                "Introspect cannot find an active token, user unauthorized",
                detail=response.text,
                resource_server_id=self.resource_server_id,
                openid_url=self.openid_url,
            )
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail=response.text)

        return OIDCUserModel(data)


async def _get_decision(async_request: AsyncClient, opa_url: str, opa_input: dict) -> OPAResult:
    logger.debug("Posting input json to Policy agent", opa_url=opa_url, input=opa_input)
    try:
        result = await async_request.post(opa_url, json=opa_input)
    except (NetworkError, TypeError) as exc:
        logger.debug("Could not get decision from policy agent", error=str(exc))
        raise HTTPException(status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail="Policy agent is unavailable")

    return OPAResult.parse_obj(result.json())


def _evaluate_decision(decision: OPAResult, auto_error: bool, **context: dict[str, Any]) -> bool:
    did = decision.decision_id

    if decision.result:
        logger.debug("User is authorized to access the resource", decision_id=did, **context)
        return True

    logger.debug("User is not allowed to access the resource", decision_id=did, **context)
    if not auto_error:
        return False

    raise HTTPException(
        status_code=HTTPStatus.FORBIDDEN,
        detail=f"User is not allowed to access resource: {context.get('resource')} Decision was taken with id: {did}",
    )


def opa_decision(
    opa_url: str,
    oidc_security: OIDCUser,
    auto_error: bool = True,
    opa_kwargs: Union[Mapping[str, str], None] = None,
) -> Callable[[Request, OIDCUserModel, AsyncClient], Awaitable[Union[bool, None]]]:
    async def _opa_decision(
        request: Request,
        user_info: OIDCUserModel = Depends(oidc_security),
        async_request: AsyncClient = Depends(_make_async_client),
    ) -> Union[bool, None]:
        """Check OIDCUserModel against the OPA policy.

        This is used as a security module in Fastapi projects
        This method will make an async call towards the Policy agent.

        Args:
            request: Request object that will be used to retrieve request metadata.
            user_info: The OIDCUserModel object that will be checked
            async_request: The httpx client.
        """

        if not (oauth2lib_settings.OAUTH2_ACTIVE and oauth2lib_settings.OAUTH2_AUTHORIZATION_ACTIVE):
            return None

        try:
            json = await request.json()
        # Silencing the Decode error or Type error when request.json() does not return anything sane.
        # Some requests do not have a json response therefore as this code gets called on every request
        # we need to suppress the `None` case (TypeError) or the `other than json` case (JSONDecodeError)
        # Suppress AttributeError in case of websocket request, it doesn't have .json
        except (JSONDecodeError, TypeError, ClientDisconnect, AttributeError):
            json = {}

        # defaulting to GET request method for WebSocket request, it doesn't have .method
        request_method = request.method if hasattr(request, "method") else "GET"
        opa_input = {
            "input": {
                **(opa_kwargs or {}),
                **user_info,
                "resource": request.url.path,
                "method": request_method,
                "arguments": {"path": request.path_params, "query": {**request.query_params}, "json": json},
            }
        }

        decision = await _get_decision(async_request, opa_url, opa_input)

        context = {
            "resource": opa_input["input"]["resource"],
            "method": opa_input["input"]["method"],
            "user_info": user_info,
            "input": opa_input,
            "url": request.url,
        }
        return _evaluate_decision(decision, auto_error, **context)

    return _opa_decision


def opa_graphql_decision(
    opa_url: str,
    _oidc_security: OIDCUser,
    auto_error: bool = False,  # By default don't raise HTTP 403 because partial results are preferred
    opa_kwargs: Union[Mapping[str, str], None] = None,
    async_request: Union[AsyncClient, None] = None,
) -> Callable[[str, OIDCUserModel], Awaitable[Union[bool, None]]]:
    async def _opa_decision(
        path: str,
        oidc_user: OIDCUserModel = Depends(_oidc_security),
        async_request_1: Union[AsyncClient, None] = None,
    ) -> Union[bool, None]:
        """Check OIDCUserModel against the OPA policy.

        This is used as a security module in Graphql projects
        This method will make an async call towards the Policy agent.

        Args:
            path: the graphql path that will be checked against the permissions of the oidc_user
            oidc_user: The OIDCUserModel object that will be checked
            async_request_1: The Async client
        """
        if not (oauth2lib_settings.OAUTH2_ACTIVE and oauth2lib_settings.OAUTH2_AUTHORIZATION_ACTIVE):
            return None

        opa_input = {
            "input": {
                **(opa_kwargs or {}),
                **oidc_user,
                "resource": path,
                "method": "POST",
            }
        }

        client_request = async_request or async_request_1
        if not client_request:
            client_request = AsyncClient(http1=True, verify=HTTPX_SSL_CONTEXT)

        decision = await _get_decision(client_request, opa_url, opa_input)

        context = {"resource": opa_input["input"]["resource"], "input": opa_input}
        return _evaluate_decision(decision, auto_error, **context)

    return _opa_decision
