from typing import cast
from unittest import mock

import pytest
from fastapi.exceptions import HTTPException
from fastapi.requests import Request
from fastapi.websockets import WebSocket
from httpx import AsyncClient, BasicAuth, Response

from oauth2_lib.fastapi import OIDCConfig, OIDCUser, OIDCUserModel, opa_decision

discovery = {
    "issuer": "https://connect.test.surfconext.nl",
    "authorization_endpoint": "https://connect.test.surfconext.nl/oidc/authorize",
    "token_endpoint": "https://connect.test.surfconext.nl/oidc/token",
    "userinfo_endpoint": "https://connect.test.surfconext.nl/oidc/userinfo",
    "introspect_endpoint": "https://connect.test.surfconext.nl/oidc/introspect",
    "jwks_uri": "https://connect.test.surfconext.nl/oidc/certs",
    "response_types_supported": [
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "token id_token",
        "code token id_token",
    ],
    "response_modes_supported": ["fragment", "query", "form_post"],
    "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "client_credentials"],
    "subject_types_supported": ["public", "pairwise"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "groups", "profile", "email", "address", "phone"],
    "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    "claims_supported": [
        "aud",
        "nbf",
        "iss",
        "exp",
        "iat",
        "jti",
        "nonce",
        "at_hash",
        "c_hash",
        "s_hash",
        "at_hash",
        "auth_time",
        "sub",
        "edumember_is_member_of",
        "eduperson_affiliation",
        "eduperson_entitlement",
        "eduperson_principal_name",
        "eduperson_scoped_affiliation",
        "email",
        "email_verified",
        "family_name",
        "given_name",
        "name",
        "nickname",
        "preferred_username",
        "schac_home_organization",
        "schac_home_organization_type",
        "schac_personal_unique_code",
        "eduperson_orcid",
        "eckid",
        "surf-crm-id",
        "uids",
    ],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "code_challenge_methods_supported": ["plain", "S256"],
}


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


class MockBasicAuth(BasicAuth):
    """A helper object that compares equal to BasicAuth."""

    def __eq__(self, other):
        return isinstance(other, BasicAuth) and self._auth_header == other._auth_header


@pytest.mark.asyncio
async def test_openid_config(make_mock_async_client):
    openid_bearer = OIDCUser("openid_url", "id", "secret")

    mock_async_client = make_mock_async_client(discovery)

    await openid_bearer.check_openid_config(mock_async_client)

    assert openid_bearer.openid_config == OIDCConfig.parse_obj(discovery)

    mock_async_client.get.assert_called_once_with("openid_url/.well-known/openid-configuration")


@pytest.mark.asyncio
async def test_introspect_token(make_mock_async_client):
    openid_bearer = OIDCUser("openid_url", "id", "secret")
    openid_bearer.openid_config = OIDCConfig.parse_obj(discovery)

    mock_async_client = make_mock_async_client(user_info_matching)

    result = await openid_bearer.introspect_token(mock_async_client, access_token)

    assert result == user_info_matching

    mock_async_client.post.assert_called_once_with(
        discovery["introspect_endpoint"],
        auth=MockBasicAuth("id", "secret"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        params={"token": access_token},
    )


@pytest.mark.asyncio
async def test_introspect_exception():
    openid_bearer = OIDCUser("openid_url", "id", "secret")
    openid_bearer.openid_config = OIDCConfig.parse_obj(discovery)

    mock_async_client = mock.MagicMock(spec=AsyncClient)

    async def mock_request(*args, **kwargs):
        mock_response = mock.MagicMock(spec=Response)
        mock_response.status_code = 400
        mock_response.text = "error"
        mock_response.json.return_value = {"error": "error"}
        return mock_response

    mock_async_client.post.side_effect = mock_request

    with pytest.raises(HTTPException) as exception:
        await openid_bearer.introspect_token(mock_async_client, access_token)

    assert exception.value.detail == "error"

    mock_async_client.post.assert_called_once_with(
        discovery["introspect_endpoint"],
        auth=MockBasicAuth("id", "secret"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        params={"token": access_token},
    )


@pytest.mark.asyncio
async def test_OIDCUser():

    mock_request = mock.MagicMock(spec=Request)
    mock_request.headers = {"Authorization": "Bearer creds"}

    async def mock_introspect_token(client, token):
        return user_info_matching

    openid_bearer = OIDCUser("openid_url", "id", "secret")
    openid_bearer.openid_config = OIDCConfig.parse_obj(discovery)
    openid_bearer.introspect_token = mock_introspect_token  # type:ignore

    result = await openid_bearer(mock_request)

    assert result == user_info_matching


@pytest.mark.asyncio
async def test_OIDCUser_with_token():

    mock_request = mock.MagicMock(spec=Request)
    mock_request.headers = {"Authorization": "Bearer creds"}

    async def mock_introspect_token(client, token):
        return user_info_matching

    openid_bearer = OIDCUser("openid_url", "id", "secret")
    openid_bearer.openid_config = OIDCConfig.parse_obj(discovery)
    openid_bearer.introspect_token = mock_introspect_token  # type:ignore

    result = await openid_bearer(mock_request, token="creds")  # noqa: S106

    assert result == user_info_matching


@pytest.mark.asyncio
async def test_OIDCUser_incompatible_schema():
    mock_request = mock.MagicMock(spec=Request)
    mock_request.headers = {"Authorization": "basic creds"}

    openid_bearer = OIDCUser("openid_url", "id", "secret")
    openid_bearer.openid_config = OIDCConfig.parse_obj(discovery)

    with pytest.raises(HTTPException) as exception:
        await openid_bearer(mock_request)

    assert exception.value.status_code == 403


@pytest.mark.asyncio
async def test_OIDCUser_invalid():
    mock_request = mock.MagicMock(spec=Request)
    mock_request.headers = {"Authorization": "Bearer creds"}

    async def mock_introspect_token(client, token):
        return {"wrong_data": "wrong_data"}

    openid_bearer = OIDCUser("openid_url", "id", "secret")
    openid_bearer.openid_config = OIDCConfig.parse_obj(discovery)
    openid_bearer.introspect_token = mock_introspect_token  # type:ignore

    with pytest.raises(HTTPException) as exception:
        await openid_bearer(mock_request)

    assert exception.value.status_code == 401


@pytest.mark.asyncio
async def test_OIDCUser_no_creds_no_error():
    mock_request = mock.MagicMock(spec=Request)
    mock_request.headers = {}

    async def mock_introspect_token(client, token):
        return {"wrong_data": "wrong_data"}

    openid_bearer = OIDCUser("openid_url", "id", "secret", auto_error=False)
    openid_bearer.openid_config = OIDCConfig.parse_obj(discovery)
    openid_bearer.introspect_token = mock_introspect_token  # type:ignore

    result = await openid_bearer(mock_request, None)  # type:ignore

    assert result is None


@pytest.mark.asyncio
async def test_OIDCUser_disabled():
    mock_request = mock.MagicMock(spec=Request)
    mock_request.headers = {"Authorization": "Bearer creds"}

    async def mock_introspect_token(client, token):
        return {"wrong_data": "wrong_data"}

    openid_bearer = OIDCUser("openid_url", "id", "secret", enabled=False)
    openid_bearer.openid_config = OIDCConfig.parse_obj(discovery)
    openid_bearer.introspect_token = mock_introspect_token  # type:ignore

    result = await openid_bearer(mock_request)

    assert result is None


@pytest.mark.asyncio
async def test_opa_decision_auto_error():
    def mock_user_info():
        return {}

    opa_decision_security = opa_decision("https://opa_url.test", cast(OIDCUser, mock_user_info), enabled=False)

    mock_request = mock.MagicMock(spec=Request)

    assert await opa_decision_security(mock_request, {}, None) is None  # type:ignore


@pytest.fixture
def mock_request():
    mock_request = mock.MagicMock(spec=Request)
    mock_request.url.path = "/test/path"
    mock_request.method = "GET"
    mock_request.path_params = {}
    mock_request.json.return_value = {}
    return mock_request


@pytest.fixture
def mock_websocket_request():
    mock_request = mock.MagicMock(spec=WebSocket)
    mock_request.url.path = "/test/path"
    mock_request.path_params = {}
    return mock_request


@pytest.mark.asyncio
async def test_opa_decision_user_not_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": False, "decision_id": "hoi"})

    opa_decision_security = opa_decision("https://opa_url.test", None)  # type:ignore

    with pytest.raises(HTTPException) as exception:
        await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert exception.value.status_code == 403
    opa_input = {
        "input": {
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


# @pytest.mark.asyncio
# async def test_opa_decision_opa_unavailable(make_mock_async_client, mock_request):
#     mock_async_client = make_mock_async_client({"result": False, "decision_id": "hoi"})

#     opa_decision_security = opa_decision("https://opa_url.test", None)

#     with pytest.raises(HTTPException) as exception:
#         await opa_decision_security(mock_request, user_info_matching, mock_async_client)
#     assert exception.value.status_code == 503


@pytest.mark.asyncio
async def test_opa_decision_network_or_type_error(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client(error=TypeError())

    opa_decision_security = opa_decision("https://opa_url.test", None)  # type:ignore

    with pytest.raises(HTTPException) as exception:
        await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert exception.value.status_code == 503


@pytest.mark.asyncio
async def test_opa_decision_user_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})

    opa_decision_security = opa_decision("https://opa_url.test", None)  # type:ignore

    result = await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_user_allowed_websocket_request(make_mock_async_client, mock_websocket_request):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})

    opa_decision_security = opa_decision("https://opa_url.test", None)  # type:ignore

    result = await opa_decision_security(mock_websocket_request, user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_kwargs(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})

    opa_decision_security = opa_decision("https://opa_url.test", None, opa_kwargs={"extra": 3})  # type:ignore

    result = await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            "extra": 3,
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_auto_error_not_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": False, "decision_id": "hoi"})

    opa_decision_security = opa_decision(
        "https://opa_url.test", None, opa_kwargs={"extra": 3}, auto_error=False  # type:ignore
    )

    result = await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert result is False
    opa_input = {
        "input": {
            "extra": 3,
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


@pytest.mark.asyncio
async def test_opa_decision_auto_error_allowed(make_mock_async_client, mock_request):
    mock_async_client = make_mock_async_client({"result": True, "decision_id": "hoi"})

    opa_decision_security = opa_decision(
        "https://opa_url.test", None, opa_kwargs={"extra": 3}, auto_error=False  # type:ignore
    )
    result = await opa_decision_security(mock_request, user_info_matching, mock_async_client)

    assert result is True
    opa_input = {
        "input": {
            "extra": 3,
            **user_info_matching,
            "resource": "/test/path",
            "method": "GET",
            "arguments": {"path": {}, "query": {}, "json": {}},
        }
    }
    mock_async_client.post.assert_called_with("https://opa_url.test", json=opa_input)


def test_OIDCUserModel():
    user_model = OIDCUserModel(**user_info_matching)
    assert user_model.user_name == ""
    assert user_model.display_name == ""
    assert user_model.principal_name == "doe@surfnet.nl"
    assert user_model.email == "john.doe@surfnet.nl"
    assert len(user_model.memberships) == 1
    assert len(user_model.teams) == 0
    assert len(user_model.entitlements) == 1
    assert len(user_model.roles) == 1
    assert user_model.roles == {"role0"}
    assert user_model.organization_codes == set()
    assert user_model.organization_guids == set()
    assert user_model.scopes == {"openid", "test:scope"}
