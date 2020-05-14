from asyncio import new_event_loop
from http import HTTPStatus
from typing import Any, Dict

import opentracing
import structlog
from authlib.integrations.base_client import BaseOAuth, RemoteApp
from opentracing.propagation import Format

logger = structlog.get_logger(__name__)


def is_api_exception(ex: Exception) -> bool:
    """Test for swagger-codegen ApiException.

    For each API, swagger-codegen generates a new ApiException class. These are not organized into
    a hierarchy. Hence testing whether one is dealing with one of the ApiException classes without knowing how
    many there are and where they are located, needs some special logic.

    Args:
        ex: the Exception to be tested.

    Returns:
        True if it is an ApiException, False otherwise.

    """
    return ex.__class__.__name__ == "ApiException"


class AsyncAuthMixin:
    """Authorization mixin for swagger-codegen generated ApiClients.

    This mixin ensures the proper OAuth2 header is set for API calls if OAuth2 has been enabled. It will also try
    to refresh the token and retry the call if it expects the token to be expired.

    IMPORTANT: AsyncAuthMixin should be the first class in the inheritance list!

    Given a Fubar API. Usage is::

        import fubar_client

        class FubarApiClient(AuthMixin, fubar_client.ApiClient)
            pass

    Calls to the Fubar API can now be make as follows::

        from fubar_client import BlahApi

        fac = FubarApiClient('https://api.staging.automation.surf.net/fubar')
        foo = await BlaApi(fac).get_foo_by_id(foo_id)

    """

    def __init__(
        self,
        oauth_client: BaseOAuth,
        oauth_client_name: str,
        oauth_active: bool,
        tracing_enabled: bool = False,
        *args: Any,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)  # type:ignore
        self._oauth_client: RemoteApp = getattr(oauth_client, oauth_client_name)
        self._oauth_active = oauth_active
        self._token_acquired = False
        self._token = None
        self._tracing_enabled = tracing_enabled

    async def acquire_token(self) -> None:
        if self._token_acquired:
            return
        else:
            if self._oauth_active:
                logger.debug("OAuth2 enabled. Requesting access token.", client=self.__class__.__name__)
                await self.get_client_creds_token()

    def add_client_creds_token_header(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Add header with credentials to existing set of headers.

        This function assumes the `access_token` has been set in the application configuration
        by `get_client_creds_token`.

        Args:
            headers: Existing set of headers that need to be extend with an Authorization header.

        Returns:
            New set of headers.

        """
        if self._token:
            access_token = self._token
            headers["Authorization"] = f"bearer {access_token['access_token']}"
        return headers

    async def get_client_creds_token(self, force: bool = False) -> None:
        """Conditionally fetch access_token.

        Args:
            app: Application object that has a config attribute.
            force: Force the fetch, even if the access_token is already in the application configuration.

        """
        if self._token_acquired and not force:
            return
        elif force:
            self._token = await self._oauth_client.fetch_access_token()
        else:
            self._token = await self._oauth_client.fetch_access_token()
            self._token_acquired = True

    def request(
        self,
        method,
        url,
        query_params=None,
        headers=None,
        post_params=None,
        body=None,
        _preload_content=True,
        _request_timeout=None,
    ):
        loop = new_event_loop()
        loop.run_until_complete(self.acquire_token())
        if self._tracing_enabled:
            span = opentracing.tracer.active_span
            opentracing.tracer.inject(span, Format.HTTP_HEADERS, headers)

        try:
            headers = self.add_client_creds_token_header(headers)
            return super().request(
                method, url, query_params, headers, post_params, body, _preload_content, _request_timeout,
            )
        except Exception as ex:
            if is_api_exception(ex) and ex.status in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
                logger.warning("Access Denied. Token expired? Retrying.", api_exception=str(ex))
                loop.run_until_complete(self.get_client_creds_token(force=True))
                headers = self.add_client_creds_token_header(headers)
                return super().request(
                    method, url, query_params, headers, post_params, body, _preload_content, _request_timeout,
                )

            else:
                logger.exception("Could not call API.", client=self.__class__.__name__)
                raise
