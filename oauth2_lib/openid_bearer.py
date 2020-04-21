from http import HTTPStatus
from typing import List, Optional

from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer
from httpx import AsyncClient, BasicAuth, NetworkError
from pydantic import BaseModel
from structlog import get_logger

logger = get_logger(__name__)


class UserInfo(dict):
    """The standard claims of a UserInfo object. Defined per `Section 5.1`_.

    .. _`Section 5.1`: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    """

    #: registered claims that UserInfo supports
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

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTERED_CLAIMS:
                return self.get(key)
            raise error


class OpenIDConfig(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    introspect_endpoint: str
    jwks_uri: str
    response_types_supported: List[str]
    response_modes_supported: List[str]
    grant_types_supported: List[str]
    subject_types_supported: List[str]
    id_token_signing_alg_values_supported: List[str]
    scopes_supported: List[str]
    token_endpoint_auth_methods_supported: List[str]
    claims_supported: List[str]
    claims_parameter_supported: bool
    request_parameter_supported: bool
    acr_values_supported: List[str]
    code_challenge_methods_supported: List[str]


class OPAResult(BaseModel):
    result: bool = False
    decision_id: str


class OpenIDBearer(HTTPBearer):
    """
    OpenIDBearer class extends the HTTPBearer class to do extra verification.

    The class will act as follows:
        1. Validate the Credentials at SURFconext by calling the UserInfo endpoint
        2. When receiving an active token it will enrich the response through the database roles
        3. Call the check_user_info method to validate at the policy agent.
    """

    openid_config: Optional[OpenIDConfig] = None
    openid_url: str
    resource_server_id: str
    resource_server_secret: str
    opa_url: str

    def __init__(
        self,
        openid_url: str,
        resource_server_id: str,
        resource_server_secret: str,
        opa_url: str,
        enabled: bool = True,
        auto_error: bool = True,
    ):
        super().__init__(auto_error=auto_error)
        self.openid_url = openid_url
        self.resource_server_id = resource_server_id
        self.resource_server_secret = resource_server_secret
        self.opa_url = opa_url
        self.enabled = enabled

    async def __call__(self, request: Request) -> Optional[UserInfo]:  # type:ignore
        """
        Extend the HTTPBearer __call__ method.

        This method implements the checking of requests just before the request is called.

        Args:
            request: Starlette request method.

        Returns:
            Userinfo object.

        """
        if not self.enabled:
            return None

        await self.check_openid_config()

        credentials = await super().__call__(request)
        if credentials and credentials.scheme.lower() == "bearer":
            user_info = await self.introspect_token(credentials.credentials)

            if not user_info.get("active", False):
                logger.exception("Token is invalid")
                raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Access token is invalid")
            logger.debug("UserInfo object.", user_info=user_info)
            return await self.check_user_info(request, user_info)
        elif not self.auto_error:
            return None
        else:
            logger.debug("Invalid credentials", credentials=credentials)
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED,
                detail="Wrong authentication method: only `bearer` tokens supported",
            )

    async def check_openid_config(self) -> None:
        """Check of openid config is loaded and load if not."""
        if self.openid_config:
            return

        async with AsyncClient() as client:
            response = await client.get(self.openid_url + "/.well-known/openid-configuration")
            self.openid_config = OpenIDConfig.parse_obj(response.json())

    async def introspect_token(self, token: str) -> UserInfo:
        """
        Introspect the access token to retrieve the user info.

        Args:
            token: the access_token

        Returns:
            Userinfo from openid server

        """
        await self.check_openid_config()
        assert self.openid_config

        async with AsyncClient() as client:
            response = await client.post(
                self.openid_config.introspect_endpoint,
                params={"token": token},
                auth=BasicAuth(self.resource_server_id, self.resource_server_secret),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        data = dict(response.json())
        if response.status_code in range(400, 404):
            logger.error("Introspect cannot find an active token", error=data["error"])

            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail=response.text)
        logger.debug("Response from openid introspect", response=data)

        if "active" not in data:
            logger.debug("UserInfo invalid; Re-raising openid error as 401", original_message=data["message"])
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail=data["message"])

        return UserInfo(data)

    async def check_user_info(self, request: Request, user_info: UserInfo) -> None:
        """
        Check UserInfo against the policy.

        This method will make an async call towards the Policy agent.

        Args:
            request: Request object that will be used to retrieve request metadata.
            user_info: The UserInfo object that will be checked
        """

        if self.enabled and self.auto_error:
            opa_input = {"input": {**user_info, "resource": request.url.path, "method": request.method}}

            logger.debug("Posting input json to Policy agent", input=opa_input)

            try:
                async with AsyncClient() as client:
                    result = await client.post(self.opa_url, json=opa_input)

                data = OPAResult.parse_obj(result.json())

                if not data.result:
                    logger.error(
                        "User is not allowed to access the resource",
                        decision_id=data.decision_id,
                        resource=request.url.path,
                        method=request.method,
                        user_info=user_info,
                        input=opa_input,
                    )
                    raise HTTPException(
                        status_code=HTTPStatus.FORBIDDEN,
                        detail=f"User is not allowed to access resource: {request.url.path} Decision was taken with id: {data.decision_id}",
                    )

                logger.debug(
                    "User is authorized to access the resource",
                    decision_id=data.decision_id,
                    resource=request.url.path,
                    method=request.method,
                    user_info=user_info,
                    input=opa_input,
                )

            except (NetworkError, TypeError):
                raise HTTPException(status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail="Policy agent is unavailable")
