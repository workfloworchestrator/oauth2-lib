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
