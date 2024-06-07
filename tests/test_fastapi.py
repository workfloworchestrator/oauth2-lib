from http import HTTPStatus
from unittest import mock
from unittest.mock import AsyncMock

import pytest
from fastapi.exceptions import HTTPException
from fastapi.requests import Request
from httpx import AsyncClient, BasicAuth
from starlette.websockets import WebSocket

from oauth2_lib.fastapi import HttpBearerExtractor, OIDCAuth, OIDCConfig, OIDCUserModel
from oauth2_lib.settings import oauth2lib_settings
from tests.conftest import MockResponse

user_info = {"active": True, "uids": ["boers"], "updated_at": 1582810910, "scope": "openid test:scope", "sub": "hoi"}

user_info_matching: OIDCUserModel = {  # type:ignore
    "active": True,
    "edumember_is_member_of": ["urn:collab:org:surf.nl"],
    "eduperson_entitlement": ["urn:mace:surfnet.nl:surfnet.nl:sab:role:role0"],
    "eduperson_principal_name": "doe@surfnet.nl",
    "email": "john.doe@surfnet.nl",
    "email_verified": True,
    "family_name": "Doe",
    "given_name": "John",
    "name": "John Doe",
    "schac_home_organization": "surfnet.nl",
    "sub": "327fb66ce785099a2b9647ff05f2d57858c27d01",
    "uids": ["John"],
    "updated_at": 1582810910,
    "scope": "openid test:scope",
    "client_id": mock.ANY,
    "user_id": "test:role1",
}

id_token_response = {
    "header": {"alg": "RS256", "kid": "key_2020_02_27_00_00_00_007", "typ": "JWT"},
    "payload": {
        "acr": "http://test.surfconext.nl/assurance/loa1",
        "at_hash": "iCDx64mNeptv7et4vRcyYQ",
        "aud": "playground_client",
        "auth_time": 1582814266,
        "exp": 1583678266,
        "iat": 1582814266,
        "iss": "https://connect.test.surfconext.nl",
        "jti": "d72337e9-017f-4b7f-b855-3804f94747fd",
        "nbf": 1582814266,
        "nonce": "example",
        "s_hash": "UNhY4JhezH9gQYqvDMWrWA",
        "sub": "a962d3a5c527c6b33bc351b4e9a08d56a26d748a",
    },
}

access_token = (
    "eyJraWQiOiJrZXlfMjAyMF8wMl8yN18wMF8wMF8wMF8wMDciLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiYXBpL"  # noqa: S105
    "WdhdGV3YXkuc3RhZ2luZy5hdXRvbWF0aW9uLnN1cmYubmV0IiwiYXBpLWdhdGV3YXktcnMuc3RhZ2luZy5hdXRvbWF0aW9uLnN1cmYu"
    "bmV0Il0sInN1YiI6ImFwaS1nYXRld2F5LnN0YWdpbmcuYXV0b21hdGlvbi5zdXJmLm5ldCIsIm5iZiI6MTU4MjgxMDkxMCwiaXNzIjo"
    "iaHR0cHM6XC9cL2Nvbm5lY3QudGVzdC5zdXJmY29uZXh0Lm5sIiwiY2xhaW1zIjoiQVZ5ZkNJUENac1lwbHlueEh2S1RrUDRsSWZxYm"
    "F2WjEzXC9HK1dQdGc5VXZCbEJGYnAzbEFlbnM1VHpMOE9iaUVEZUhsbGNGTzdlZWVhdUxEMUFpaGlhMHFsYjBQNU9XZHpZNVZnUmJcL1"
    "lveGRCZHZoWUVSR1VDTHp0bXUxaTIwOVcxWFhDUGRCZmxGQkU2RVR5U0Vwalp3QUFRTHAzTkJLdjFWQnVVYkFUTjdkQURcL1VBNmV4Q1"
    "B5MTMrRmVrZnpYUE5taFNwZGpuOUplekdVNG4wOVpRMnk4WDZabmFxblNwOU1hcmlRRm1CZ1BTWUpYXC85bEowcWNFSXByTXNHemVQbW"
    "FQeDA4TWswZFdCZ091YllDK2JDcDJDcE5Pb1wvUE40SDQ5aDFQV3VzQzNcL1ppakpqUnl2ckhDcnhVMCt6Z05Mc3BGQmFTdVdUSFlKa"
    "EVOdXpmOEQwMzBaR3JNOGV2UVJPWnhyMzEwdFkyUmxSd1c4OVhPQjc4ZVdBYTNOXC93ZVwvZXMrZFNEaVY1WjFSTzZ0YWF0Y25mUUc"
    "rZitqWUlLbTdpaGJScEFQOGZFVERQUDU0Y01LUU01TFJRUXd4dmxjc29QZHd5UHVSYyswazZQTVV5T1V1TmNmQ2Q2dVwvbjB6ZmFw"
    "d01LZjBMWU9XaFhkc1dcLzRJTjNFQVFkUTlucGhaTGNIWWNYckFpMEdCUldnWEptREc5RHVOdkJjZGs5SkE2eEMyOEV5VVZSOUNHTz"
    "I2a210cjM1cGg1czVxa0FVQjJES2VGaUUyUDlVSEM1SUR3anZVOVNabUErTHdnOVlpYitQZ0R2dmptZHVka2I2VUlab3VXS0xMTnA"
    "xY3hOMDJrUUlWalVSTklZcTNyNUhQdnVvRHRkSTNNdHhWUmc0T3pzSFZLZm5xeTliRGc4TTUxbXZMb1AxXC83Vk1wZ2pQYVdnTUhJ"
    "TGhIZnFqVEF2VWtDYlVoU3VxdFVQSDI4TlFtdlN3RjJyXC82TG4zRWJLbzRjNjF1dE9CZjNtT1wvXC9YdFl2TEVcL2ttbUxJSmpLd"
    "E9sQmV4YzBVN3JvS2gxaTBNZ1pEMzFwM1piRms5MitPejAxaVJGUlBoUXRWaVJaSlNnMDlNQ1JoVUxoWVNVZnNRcVd4RmI0a1IyME"
    "NUSmV3QzltaitlbU5iK0ZkaFNpdFhuVzE2OTd1SGxiaUFlR0dVc2U0clFUMHNydGNhak5tVzI2OHplQUtPQ3lWa3VhMjA3XC81UW"
    "RUUkdzOTMreWk5Zm1TUXdjNWRJcVJaTGpHSXBLNjNtSHFjSDZUTDBOdUlsVmtZcnZsZDZaZDZ0bzVPeFk3ZjhxQW9zclhwUHRWbU"
    "4xUzloRFByNlZDR2tuY213dDRHdTYwMG5uTllqZE1KQzFkeTRQWXlKaExhWndRYktIQ1lQekJlWWNyOVNsaGNaUFZ3TmdhenNFe"
    "lErYjEyNmd1M2UzR2h0K2pPOWM4SXFlYWRzTElUQStDZXJMemVtd0pncVFMT2IydjRudU9XRU55Unh4ZzErY3RrK0hcL2ZHaXA5"
    "VDZcLzdTM1RZV0xUb01pRWNpOG0xODVPWkFUUFdKRVdLUTM1NXdtOFc2Z3lwT1QzR1dxMzRnMHR5ZmFrWkRJenFcL29lMjBQRWZ"
    "kc25GNUF6OERUXC9oV2RxdEJQdTl5MmRhaVBtMVp1R0RPSGpOKzdqUVVBdmdJNEFlaEhzTGpFM2tXc2JETlRKd2k2MTRaZXl4cE"
    "lTem51RG13PT0iLCJleHAiOjE1ODI4MTQ1MTAsImNsYWltX2tleV9pZCI6IjE1NTM5MjYyNzUiLCJpYXQiOjE1ODI4MTA5MTAsI"
    "mp0aSI6ImZlNDFjZjEwLWNiNDUtNGQ0NC1hNjBiLWJjNmEwZjY4ZTIxZCJ9.L6PCRoXBGFkXXDiDJsavnEluWIdS8AV0H8lPt55"
    "U104Gh_6qzkg7eM0Go1zmFhfZfzUnBBes5bbz5bgNL5pJrMgOhrhiHx1AEr1Up20iiufaKPtBoy6AgwmdMMyISU483fB6F4Qoj"
    "iqOLPc73K6rwehEsEE3izsMUKShUMBKiolDrK5Z0rvFz-pedAkXs7ocfaxIIlCZDDqSIub5rY_T6EM_l4Jdnlkl5H_2C2SkhGn"
    "z1Fc28r-YfqloKzMsbocIFUaZ_x-MCAcBfZe-1WFrpYggfAsQ2U0sQTbL25U1l68wxOr4wwno6EDfC478Jr72J3Ok56Cyal2"
    "Fb6iBHLHogg"
)
id_token = (
    "eyJraWQiOiJrZXlfMjAyMF8wMl8yN18wMF8wMF8wMF8wMDciLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNo"  # noqa: S105
    "IjoiaUNEeDY0bU5lcHR2N2V0NHZSY3lZUSIsImF1ZCI6InBsYXlncm91bmRfY2xpZW50Iiwic3ViIjoiYTk2MmQzYTVjNTI3Y"
    "zZiMzNiYzM1MWI0ZTlhMDhkNTZhMjZkNzQ4YSIsImFjciI6Imh0dHA6XC9cL3Rlc3Quc3VyZmNvbmV4dC5ubFwvYXNzdXJhbm"
    "NlXC9sb2ExIiwic19oYXNoIjoiVU5oWTRKaGV6SDlnUVlxdkRNV3JXQSIsIm5iZiI6MTU4MjgxNDI2NiwiYXV0aF90aW1lIjo"
    "xNTgyODE0MjY2LCJpc3MiOiJodHRwczpcL1wvY29ubmVjdC50ZXN0LnN1cmZjb25leHQubmwiLCJleHAiOjE1ODM2NzgyNjY"
    "sImlhdCI6MTU4MjgxNDI2Niwibm9uY2UiOiJleGFtcGxlIiwianRpIjoiZDcyMzM3ZTktMDE3Zi00YjdmLWI4NTUtMzgwNGY"
    "5NDc0N2ZkIn0.NgH_Kkghv1BjOD7YbMNEW5bAsHLxqwVQMMOotLATrZ_VKyo_xl4ojoJ20U1rXS6IFqGhreybhRN5PI29vl"
    "fpB5dnJNitHA6SYDEAvz3EQJvYwMejmKigPj6oyjWjKZ7TLCaSVwp4I4kR1HdhGmVHFZ2Qo3q1M74g3F6xtiC9ETyO8tBnY"
    "32Jhhhq1LvwXbv69MpNc5doD4wo6wZHqa36YsosTal5PJhpv_dJ54bXfakwwV36wdOKeMal1eNoX1ExQO1a7F5zL5Jb88F4"
    "H8ekvQtV-fv2NE64XneDE_M5TrtX58wsX3IvtgSY1SXC1G43s0uHrwe7pSHhayk17I7yiQ"
)


class MockBasicAuth(BasicAuth):
    """A helper object that compares equal to BasicAuth."""

    def __eq__(self, other):
        return isinstance(other, BasicAuth) and self._auth_header == other._auth_header


@pytest.fixture()
def oidc_auth():
    return OIDCAuth(
        "openid_url", "openid_url/.well-known/openid-configuration", "server_id", "server_secret", OIDCUserModel
    )


@pytest.mark.asyncio
async def test_openid_config_success(make_mock_async_client, discovery, oidc_auth):
    mock_async_client = make_mock_async_client(MockResponse(json=discovery))
    await oidc_auth.check_openid_config(mock_async_client.client)
    assert oidc_auth.openid_config == OIDCConfig.parse_obj(discovery)
    mock_async_client.client.get.assert_called_once_with("openid_url/.well-known/openid-configuration")
    assert oidc_auth.openid_config.issuer == discovery["issuer"], "OpenID configuration not loaded correctly"


@pytest.mark.asyncio
async def test_fetch_openid_config_failure(make_mock_async_client, discovery, oidc_auth):
    mock_async_client = make_mock_async_client(MockResponse(status_code=404))

    with pytest.raises(HTTPException) as exc_info:
        await oidc_auth.check_openid_config(mock_async_client.client)
    assert exc_info.value.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert exc_info.value.detail == f"Could not load openid config from {oidc_auth.openid_config_url}"


@pytest.mark.asyncio
async def test_userinfo_success_with_mock(oidc_auth):
    oidc_auth.userinfo = AsyncMock(return_value={"sub": "hoi"})
    user = await oidc_auth.userinfo(AsyncClient(), "valid_token")
    assert user["sub"] == "hoi", "User info not retrieved correctly"


def test_oidc_auth_initialization_default_extractor(oidc_auth):
    assert isinstance(
        oidc_auth.id_token_extractor, HttpBearerExtractor
    ), "Default ID token extractor should be HttpBearerExtractor"


@pytest.mark.asyncio
async def test_extract_token_success():
    request = mock.MagicMock()
    request.headers = {"Authorization": "Bearer example_token"}
    extractor = HttpBearerExtractor()
    assert await extractor.extract(request) == "example_token", "Token extraction failed"


@pytest.mark.asyncio
async def test_extract_token_returns_none():
    request = mock.MagicMock()
    request.headers = {}
    extractor = HttpBearerExtractor()
    assert await extractor.extract(request) is None


@pytest.mark.asyncio
async def test_authenticate_success(make_mock_async_client, discovery, oidc_auth):
    mock_async_client = make_mock_async_client(MockResponse(json=discovery))
    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        oidc_auth.userinfo = AsyncMock(return_value=user_info_matching)

        request = mock.MagicMock(spec=Request)
        request.headers = {"Authorization": "Bearer valid_token"}

        user = await oidc_auth.authenticate(request)
        assert user == user_info_matching, "Authentication failed for a valid token"


@pytest.mark.asyncio
async def test_authenticate_oauth2_inactive():
    oauth2lib_settings.OAUTH2_ACTIVE = False
    oidc_auth = OIDCAuth(
        "openid_url", "openid_url/.well-known/openid-configuration", "server_id", "server_secret", OIDCUserModel
    )
    result = await oidc_auth.authenticate(request=mock.MagicMock(spec=Request))
    assert result is None, "Authentication should be bypassed when OAuth2 is inactive"
    oauth2lib_settings.OAUTH2_ACTIVE = True


@pytest.mark.asyncio
async def test_authenticate_bypassable_request(make_mock_async_client, discovery):
    mock_async_client = make_mock_async_client(MockResponse(json=discovery))
    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):

        class OIDCAuthMock(OIDCAuth):
            @staticmethod
            async def is_bypassable_request(request: Request) -> bool:
                return True

        oidc_auth = OIDCAuthMock(
            "openid_url", "openid_url/.well-known/openid-configuration", "id", "secret", OIDCUserModel
        )
        result = await oidc_auth.authenticate(mock.MagicMock(spec=Request), "random_valid_token")
        assert result is None, "Authentication should return None for bypassable requests"


@pytest.mark.asyncio
async def test_authenticate_token_extraction_failure(make_mock_async_client, discovery, oidc_auth):
    mock_async_client = make_mock_async_client(MockResponse(json=discovery))
    with mock.patch("oauth2_lib.fastapi.AsyncClient", return_value=mock_async_client):
        request = mock.MagicMock(spec=Request)
        request.headers = {}

        with pytest.raises(HTTPException) as exc_info:
            await oidc_auth.authenticate(request)
            assert exc_info.value.status_code == 403
            assert exc_info.value.detail == "Not authenticated"


def test_oidc_user_model():
    user_model = OIDCUserModel(**user_info_matching)
    assert user_model.user_name == ""


@pytest.mark.asyncio
async def test_unauthenticated_websocket_request_raises_403(oidc_auth):
    oidc_auth.check_openid_config = mock.AsyncMock()
    oidc_auth.userinfo = mock.AsyncMock()

    websocket = WebSocket(scope={"type": "websocket"}, receive=mock.AsyncMock(), send=mock.AsyncMock())

    with pytest.raises(HTTPException) as exc_info:
        await oidc_auth.authenticate(websocket)

    assert exc_info.value.status_code == 403, "Expected HTTP 403 error for unauthenticated websocket request"
    assert exc_info.value.detail == "Not authenticated"
