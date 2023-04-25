from unittest import mock

import pytest
from httpx import AsyncClient, Response
from urllib3_mock import Responses


@pytest.fixture(scope="session")
def make_mock_async_client():
    def _make_mock_async_client(json=None, error=None):
        mock_async_client = mock.AsyncMock(spec=AsyncClient)

        if error:
            mock_async_client.get.side_effect = error
            mock_async_client.post.side_effect = error
        else:
            mock_response = mock.MagicMock(spec=Response)
            mock_response.json.return_value = json
            mock_response.status_code = 200

            mock_async_client.get.side_effect = [mock_response]
            mock_async_client.post.side_effect = [mock_response]

        return mock_async_client

    return _make_mock_async_client


@pytest.fixture(autouse=False)
def responses():
    responses_mock = Responses("requests.packages.urllib3")

    def _find_request(call):
        if not (mock_url := responses_mock._find_match(call.request)):
            raise Exception(f"Call not mocked: {call.request}")
        return mock_url

    def _to_tuple(url_mock):
        return (url_mock["url"], url_mock["method"], url_mock["match_querystring"])

    with responses_mock:
        yield responses_mock

        mocked_urls = map(_to_tuple, responses_mock._urls)
        used_urls = map(_to_tuple, map(_find_request, responses_mock.calls))
        if not_used := set(mocked_urls) - set(used_urls):
            pytest.fail(f"Found unused responses mocks: {not_used}", pytrace=False)


@pytest.fixture(scope="session")
def tracing():
    from opentelemetry import trace
    from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    resource = Resource(attributes={SERVICE_NAME: "oauth2-lib-unittests"})

    provider = TracerProvider(resource=resource)

    # Uncomment to print processed spans to stdout

    # from opentelemetry.sdk.trace.export import ConsoleSpanExporter
    # console_exporter = ConsoleSpanExporter()
    # console_processor = BatchSpanProcessor(console_exporter)
    # provider.add_span_processor(console_processor)

    in_memory_exporter = InMemorySpanExporter()
    in_memory_processor = BatchSpanProcessor(in_memory_exporter)
    provider.add_span_processor(in_memory_processor)

    trace.set_tracer_provider(provider)

    def strip_query_params(url: str) -> str:
        return url.split("?")[0]

    # Remove all query params from the URL attribute on the span
    URLLib3Instrumentor().instrument(url_filter=strip_query_params)

    # Return the in-memory-processor so we can inspect the generated spans
    yield in_memory_processor

    try:
        provider.shutdown()
    except Exception as exc:
        print("Error shutting down TracerProvider, ignoring:", str(exc))  # noqa: T201


@pytest.fixture(autouse=True)
def clear_spans(tracing):
    # The tracerprovider runs the entire test-session so we have to clean up the spans
    # after each test
    tracing.span_exporter.clear()
