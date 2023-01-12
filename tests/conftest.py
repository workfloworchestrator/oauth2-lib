from unittest import mock

import pytest
from httpx import AsyncClient, Response


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
