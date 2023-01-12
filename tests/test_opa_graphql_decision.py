from typing import cast

import pytest

from oauth2_lib.fastapi import OIDCUser, opa_graphql_decision


@pytest.mark.asyncio
async def test_opa_graphql_decision_auto_error():
    def mock_user_info():
        return {}

    opa_decision_security = opa_graphql_decision("https://opa_url.test", cast(OIDCUser, mock_user_info), enabled=False)

    assert await opa_decision_security("", None) is None  # type:ignore


# TODO: add more tests to increase coverage to 60+ % again
