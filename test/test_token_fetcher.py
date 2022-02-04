#  Copyright 2022 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

import random
import string
from unittest import mock
from unittest.mock import ANY

import pytest

from zepben.auth.client.token_fetcher import ZepbenTokenFetcher, AuthException, create_token_fetcher, AuthMethod

TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZha2VraWQifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci8iLCJzdWIiOiJmYWtlIiwiYXVkIjoiaHR0cHM6Ly9mYWtlLWF1ZC8iLCJpYXQiOjE1OTE4MzQxNzksImV4cCI6OTU5MTkyMDU3OSwiYXpwIjoid2U5ZDNSME5jTUNWckpDZ2ROSWVmWWx6aHo2VE9SaGciLCJzY29wZSI6IndyaXRlOm5ldHdvcmsgcmVhZDpuZXR3b3JrIHdyaXRlOm1ldHJpY3MgcmVhZDpld2IiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMiLCJwZXJtaXNzaW9ucyI6WyJ3cml0ZTpuZXR3b3JrIiwicmVhZDpuZXR3b3JrIiwid3JpdGU6bWV0cmljcyIsInJlYWQ6ZXdiIl19.ay_YTwRsfcNzVdmQ4EgmuNMMypfZIIc8K9dCCtLqUmUJDtE7NUuKaVAmGDdmW1J-ngm0UsH4k6B5QpPIJnLIROpdDf7aRzdE9hNFuSHR3arpyCzmO2-TiFDZLFXQjHf0Q-BaxGoXLQBupGYuQaG_3flaLPB3hPV0nqPoBTIoJgG8n2w0Uo2tePe_y2Blqco1sK2wElwyMlYc-UuTyFSvwKlpSXYmO4ppVmbAa9lS2ley6lcv2TwXLCk0KfIIH2E5OBvJHevZqYEzFBAeLCnahKoWxexsVvEfZr40Nhc6oPRT5yJfHRBnCrDnO1fE96rqguQpsDG-HWCtd2GkpnAXNg"

mock_audience = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_auth0_issuer_domain = ''.join(random.choices(string.ascii_lowercase, k=10)) + "auth0"
mock_access_token = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_refresh_token = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_issuer_protocol = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_auth_method = random.choice(list(AuthMethod))
mock_verify_certificate = bool(random.getrandbits(1))

class MockResponse:
    def __init__(self, json_data, status_code, reason="", text=""):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = status_code < 400
        self.reason = reason
        self.text = text

    def json(self):
        if not self.json_data:
            raise ValueError()
        return self.json_data


@mock.patch('zepben.auth.client.token_fetcher.requests.get', side_effect=lambda *args, **kwargs: MockResponse(
    {"authType": "AUTH0", "audience": mock_audience, "issuer": "test_issuer"}, 200))
def test_create_token_fetcher_success(mock_get):
    token_fetcher = create_token_fetcher("https://testaddress")
    assert token_fetcher is not None
    assert token_fetcher.audience == mock_audience
    assert token_fetcher.issuer_domain == "test_issuer"

    mock_get.assert_called_once_with(
        "https://testaddress",
        verify=True
    )


@mock.patch('zepben.auth.client.token_fetcher.requests.get', side_effect=lambda *args, **kwargs: MockResponse(
    {"authType": "NONE", "audience": "", "issuer": ""}, 200))
def test_create_token_fetcher_no_auth(mock_get):
    token_fetcher = create_token_fetcher("https://testaddress")
    assert token_fetcher is None

    mock_get.assert_called_once_with(
        "https://testaddress",
        verify=True
    )


@mock.patch('zepben.auth.client.token_fetcher.requests.get', side_effect=lambda *args, **kwargs: MockResponse(None, 404))
def test_create_token_fetcher_bad_response(mock_get):
    with pytest.raises(ValueError, match=f"https://testaddress responded with error: 404 - "):
        token_fetcher = create_token_fetcher("https://testaddress")

    mock_get.assert_called_once_with(
        "https://testaddress",
        verify=True
    )


@mock.patch('zepben.auth.client.token_fetcher.requests.get', side_effect=lambda *args, **kwargs: MockResponse(None, 200, reason='test reason', text='test text'))
def test_create_token_fetcher_missing_json(mock_get):
    with pytest.raises(ValueError, match=f"Expected JSON response from https://testaddress, but got: test text."):
        token_fetcher = create_token_fetcher("https://testaddress")

    mock_get.assert_called_once_with(
        "https://testaddress",
        verify=True
    )


class TestZepbentoken_fetcher:

    @mock.patch('zepben.auth.client.token_fetcher.requests.post', side_effect=lambda *args, **kwargs: MockResponse(
        {"access_token": TOKEN, "refresh_token": mock_refresh_token, "token_type": "Bearer"}, 200))
    def test_fetch_token_successful(self, mock_post):
        token_fetcher = ZepbenTokenFetcher(
            audience=mock_audience,
            issuer_domain=mock_auth0_issuer_domain,
            auth_method=mock_auth_method,
            verify_certificate=mock_verify_certificate,
            issuer_protocol=mock_issuer_protocol,
            token_path="/fake/path"
        )

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        assert f"Bearer {TOKEN}" == token_fetcher.fetch_token()  # Token from response payload is returned

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=token_fetcher.token_request_data,
            verify=mock_verify_certificate
        )  # Appropriate-looking password grant request was made to the issuer

    @mock.patch('zepben.auth.client.token_fetcher.requests.post', side_effect=lambda *args, **kwargs: MockResponse(None, 404, "test reason", "test text"))
    def test_fetch_token_throws_exception_on_bad_response(self, mock_post):
        token_fetcher = ZepbenTokenFetcher(
            audience=mock_audience,
            issuer_domain=mock_auth0_issuer_domain,
            auth_method=mock_auth_method,
            verify_certificate=mock_verify_certificate,
            issuer_protocol=mock_issuer_protocol,
            token_path="/fake/path"
        )

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        with pytest.raises(AuthException, match=f"Token fetch failed, Error was: 404 - test reason test text"):
            token_fetcher.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=token_fetcher.token_request_data,
            verify=mock_verify_certificate
        )

    @mock.patch('zepben.auth.client.token_fetcher.requests.post', side_effect=lambda *args, **kwargs: MockResponse(None, 200, "test reason", "test text"))
    def test_fetch_token_throws_exception_on_missing_json(self, mock_post):
        token_fetcher = ZepbenTokenFetcher(
            audience=mock_audience,
            issuer_domain=mock_auth0_issuer_domain,
            auth_method=mock_auth_method,
            verify_certificate=mock_verify_certificate,
            issuer_protocol=mock_issuer_protocol,
            token_path="/fake/path"
        )

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        with pytest.raises(AuthException, match=f'Response did not contain expected JSON - response was: test text'):
            token_fetcher.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=token_fetcher.token_request_data,
            verify=mock_verify_certificate
        )

    @mock.patch('zepben.auth.client.token_fetcher.requests.post',
                side_effect=lambda *args, **kwargs: MockResponse({'error': 'fail', 'error_description': 'test error description'}, 200))
    def test_fetch_token_throws_exception_on_error_response(self, mock_post):
        token_fetcher = ZepbenTokenFetcher(
            audience=mock_audience,
            issuer_domain=mock_auth0_issuer_domain,
            auth_method=mock_auth_method,
            verify_certificate=mock_verify_certificate,
            issuer_protocol=mock_issuer_protocol,
            token_path="/fake/path"
        )

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        with pytest.raises(AuthException, match=f'fail - test error description'):
            token_fetcher.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=token_fetcher.token_request_data,
            verify=mock_verify_certificate
        )

    @mock.patch('zepben.auth.client.token_fetcher.requests.post',
                side_effect=lambda *args, **kwargs: MockResponse({'test': 'fail'}, 200))
    def test_fetch_token_throws_exception_on_missing_access_token(self, mock_post):
        token_fetcher = ZepbenTokenFetcher(
            audience=mock_audience,
            issuer_domain=mock_auth0_issuer_domain,
            auth_method=mock_auth_method,
            verify_certificate=mock_verify_certificate,
            issuer_protocol=mock_issuer_protocol,
            token_path="/fake/path"
        )

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        with pytest.raises(AuthException, match="Access Token absent in token response - Response was: {'test': 'fail'}"):
            token_fetcher.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=token_fetcher.token_request_data,
            verify=mock_verify_certificate
        )

    @mock.patch('zepben.auth.client.token_fetcher.requests.post', side_effect=lambda *args, **kwargs: MockResponse(
        {"access_token": TOKEN, "refresh_token": mock_refresh_token, "token_type": "Bearer"}, 200))
    def test_fetch_token_successful_using_refresh(self, mock_post):
        token_fetcher = ZepbenTokenFetcher(
            audience=mock_audience,
            issuer_domain=mock_auth0_issuer_domain,
            auth_method=mock_auth_method,
            verify_certificate=mock_verify_certificate,
            issuer_protocol=mock_issuer_protocol,
            token_path="/fake/path"
        )

        token_fetcher.refresh_request_data['refresh_token'] = mock_refresh_token
        mock_post.assert_not_called()  # POST request is not made before get_token() is called
        token_fetcher._refresh_token = mock_refresh_token
        assert f"Bearer {TOKEN}" == token_fetcher.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=token_fetcher.refresh_request_data,
            verify=mock_verify_certificate
        )
