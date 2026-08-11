"""Guard on `verify=HTTPX_SSL_CONTEXT`, which nothing else in the suite covers.

Every other test patches `AsyncClient` wholesale, so the kwarg could be dropped and stay green.
`http1=True` is asserted too, but only because it is what the code passes — `http2` already defaults
to False, so it carries no security weight.
"""

from unittest import mock

from oauth2_lib.fastapi import HTTPX_SSL_CONTEXT, _new_async_client


def test_client_pins_ssl_context_and_http1():
    with mock.patch("oauth2_lib.fastapi.AsyncClient") as async_client:
        _new_async_client()

    assert async_client.call_args_list == [mock.call(http1=True, verify=HTTPX_SSL_CONTEXT)]
