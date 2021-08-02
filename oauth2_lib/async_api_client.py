# Copyright 2019-2020 SURF.
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
import contextlib
from asyncio import new_event_loop
from http import HTTPStatus
from typing import Any, Dict, Generator, Optional

import structlog
import urllib3
from authlib.integrations.base_client import BaseOAuth, RemoteApp
from opentelemetry import context  # type: ignore
from opentelemetry.instrumentation.utils import http_status_to_status_code
from opentelemetry.instrumentation.version import __version__
from opentelemetry.propagate import inject  # type: ignore
from opentelemetry.trace import Span, SpanKind, get_tracer  # type: ignore
from opentelemetry.trace.status import Status

logger = structlog.get_logger(__name__)

_SUPPRESS_HTTP_INSTRUMENTATION_KEY = "suppress_http_instrumentation"


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


def _apply_response(span: Span, response: urllib3.response.HTTPResponse) -> None:
    if not span.is_recording():
        return
    span.set_attribute("http.status_code", response.status)
    span.set_attribute("http.status_text", response.reason)
    span.set_status(Status(http_status_to_status_code(response.status)))


@contextlib.contextmanager
def _suppress_further_instrumentation() -> Generator:
    token = context.attach(context.set_value(_SUPPRESS_HTTP_INSTRUMENTATION_KEY, True))
    try:
        yield
    finally:
        context.detach(token)


def _is_instrumentation_suppressed() -> bool:
    return bool(context.get_value("suppress_instrumentation") or context.get_value(_SUPPRESS_HTTP_INSTRUMENTATION_KEY))


class AsyncAuthMixin:
    """Authorization mixin for swagger-codegen generated ApiClients.

    This mixin ensures the proper OAuth2 header is set for API calls if OAuth2 has been enabled. It will also try
    to refresh the token and retry the call if it expects the token to be expired.

    IMPORTANT: AsyncAuthMixin should be the first class in the inheritance list!

    Given a Fubar API. Usage is::

        import fubar_client

        class FubarApiClient(AuthMixin, fubar_client.ApiClient)
            pass

    Calls to the Fubar API can now be made as follows:

        from fubar_client import BlahApi

        fac = FubarApiClient('https://api.staging.automation.surf.net/fubar')
        foo = await BlaApi(fac).get_foo_by_id(foo_id)

    """

    _token: Optional[Dict]

    def __init__(
        self,
        oauth_client: BaseOAuth,
        oauth_client_name: str,
        oauth_active: bool,
        tracing_enabled: bool,
        *args: Any,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)  # type:ignore
        self._oauth_client: RemoteApp = getattr(oauth_client, oauth_client_name)
        self._oauth_active = oauth_active
        self._tracing_enabled = tracing_enabled
        self._token = None

    def add_client_creds_token_header(self, headers: Dict[str, Any]) -> None:
        """Add header with credentials to an existing set of headers.

        This function assumes the `access_token` has been set in the application configuration
        by `refresh_client_creds_token or by acquire_token`.

        Args:
            headers: Existing set of headers that need to be extended with an Authorization header.

        Returns:
            New set of headers.

        """
        if not self._token and self._oauth_active:
            loop = new_event_loop()
            loop.run_until_complete(self.refresh_client_creds_token())
        if self._token:
            access_token = self._token
            headers["Authorization"] = f"bearer {access_token['access_token']}"

    async def refresh_client_creds_token(self, force: bool = False) -> None:
        """
        Conditionally fetch access_token.

        This method will either set the token if it is not set or reset the token if Force is added,
        otherwise it will just return.

        Args:
            force: Force the fetch, even if the access_token is already in the application configuration.

        """
        if self._token and not force:
            return
        elif force:
            self._token = await self._oauth_client.fetch_access_token()
        else:
            self._token = await self._oauth_client.fetch_access_token()

    def request(  # type:ignore
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
        headers = {} if headers is None else headers

        span_attributes = {
            "http.method": method,
            "http.url": url,
        }

        with get_tracer(__name__, __version__).start_as_current_span(
            f"External Api Call {self.__class__.__name__}", kind=SpanKind.CLIENT, attributes=span_attributes
        ) as span:
            try:
                self.add_client_creds_token_header(headers)

                if self._tracing_enabled and not _is_instrumentation_suppressed():
                    inject(type(headers).__setitem__, headers)

                with _suppress_further_instrumentation():
                    response = super().request(  # type:ignore
                        method, url, query_params, headers, post_params, body, _preload_content, _request_timeout
                    )
                _apply_response(span, response)
                return response
            except Exception as ex:
                if is_api_exception(ex) and ex.status in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):  # type:ignore
                    logger.warning("Access Denied. Token expired? Retrying.", api_exception=str(ex))
                    loop = new_event_loop()
                    loop.run_until_complete(self.refresh_client_creds_token(force=True))
                    self.add_client_creds_token_header(headers)

                    if self._tracing_enabled and not _is_instrumentation_suppressed():
                        inject(type(headers).__setitem__, headers)

                    with _suppress_further_instrumentation():
                        response = super().request(  # type:ignore
                            method, url, query_params, headers, post_params, body, _preload_content, _request_timeout
                        )
                    _apply_response(span, response)
                    return response

                else:
                    logger.exception("Could not call API.", client=self.__class__.__name__)
                    _apply_response(span, ex)
                    raise
