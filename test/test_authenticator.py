#  Copyright 2020 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

import random
import string
from unittest import mock
from unittest.mock import ANY

import pytest

from zepben.auth.authenticator import ZepbenAuthenticator, AuthException, create_authenticator

TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZha2VraWQifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci8iLCJzdWIiOiJmYWtlIiwiYXVkIjoiaHR0cHM6Ly9mYWtlLWF1ZC8iLCJpYXQiOjE1OTE4MzQxNzksImV4cCI6OTU5MTkyMDU3OSwiYXpwIjoid2U5ZDNSME5jTUNWckpDZ2ROSWVmWWx6aHo2VE9SaGciLCJzY29wZSI6IndyaXRlOm5ldHdvcmsgcmVhZDpuZXR3b3JrIHdyaXRlOm1ldHJpY3MgcmVhZDpld2IiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMiLCJwZXJtaXNzaW9ucyI6WyJ3cml0ZTpuZXR3b3JrIiwicmVhZDpuZXR3b3JrIiwid3JpdGU6bWV0cmljcyIsInJlYWQ6ZXdiIl19.ay_YTwRsfcNzVdmQ4EgmuNMMypfZIIc8K9dCCtLqUmUJDtE7NUuKaVAmGDdmW1J-ngm0UsH4k6B5QpPIJnLIROpdDf7aRzdE9hNFuSHR3arpyCzmO2-TiFDZLFXQjHf0Q-BaxGoXLQBupGYuQaG_3flaLPB3hPV0nqPoBTIoJgG8n2w0Uo2tePe_y2Blqco1sK2wElwyMlYc-UuTyFSvwKlpSXYmO4ppVmbAa9lS2ley6lcv2TwXLCk0KfIIH2E5OBvJHevZqYEzFBAeLCnahKoWxexsVvEfZr40Nhc6oPRT5yJfHRBnCrDnO1fE96rqguQpsDG-HWCtd2GkpnAXNg"

mock_audience = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_auth0_issuer_domain = ''.join(random.choices(string.ascii_lowercase, k=10)) + "auth0"
mock_access_token = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_refresh_token = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_issuer_protocol = ''.join(random.choices(string.ascii_lowercase, k=10))


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


@mock.patch('zepben.auth.authenticator.requests.get', side_effect=lambda *args, **kwargs: MockResponse(
    {"authType": "AUTH0", "audience": mock_audience, "issuer": "test_issuer"}, 200))
def test_create_authenticator_success(mock_get):
    authenticator = create_authenticator("https://testaddress")
    assert authenticator is not None
    assert authenticator.audience == mock_audience
    assert authenticator.issuer_domain == "test_issuer"

    mock_get.assert_called_once_with(
        "https://testaddress",
        verify=True
    )


@mock.patch('zepben.auth.authenticator.requests.get', side_effect=lambda *args, **kwargs: MockResponse(
    {"authType": "NONE", "audience": "", "issuer": ""}, 200))
def test_create_authenticator_no_auth(mock_get):
    authenticator = create_authenticator("https://testaddress")
    assert authenticator is None

    mock_get.assert_called_once_with(
        "https://testaddress",
        verify=True
    )


@mock.patch('zepben.auth.authenticator.requests.get', side_effect=lambda *args, **kwargs: MockResponse(None, 404))
def test_create_authenticator_bad_response(mock_get):
    with pytest.raises(ValueError, match=f"https://testaddress responded with error: 404 - "):
        authenticator = create_authenticator("https://testaddress")

    mock_get.assert_called_once_with(
        "https://testaddress",
        verify=True
    )


@mock.patch('zepben.auth.authenticator.requests.get', side_effect=lambda *args, **kwargs: MockResponse(None, 200, reason='test reason', text='test text'))
def test_create_authenticator_missing_json(mock_get):
    with pytest.raises(ValueError, match=f"Expected JSON response from https://testaddress, but got: test text."):
        authenticator = create_authenticator("https://testaddress")

    mock_get.assert_called_once_with(
        "https://testaddress",
        verify=True
    )


class TestZepbenAuthenticator:

    @mock.patch('zepben.auth.authenticator.requests.post', side_effect=lambda *args, **kwargs: MockResponse(
        {"access_token": TOKEN, "refresh_token": mock_refresh_token, "token_type": "Bearer"}, 200))
    def test_fetch_token_successful(self, mock_post):
        authenticator = ZepbenAuthenticator(audience=mock_audience, issuer_domain=mock_auth0_issuer_domain, issuer_protocol=mock_issuer_protocol,
                                            token_path="/fake/path")

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        assert f"Bearer {TOKEN}" == authenticator.fetch_token()  # Token from response payload is returned

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=authenticator.token_request_data
        )  # Appropriate-looking password grant request was made to the issuer

    @mock.patch('zepben.auth.authenticator.requests.post', side_effect=lambda *args, **kwargs: MockResponse(None, 404, "test reason", "test text"))
    def test_fetch_token_throws_exception_on_bad_response(self, mock_post):
        authenticator = ZepbenAuthenticator(audience=mock_audience, issuer_domain=mock_auth0_issuer_domain, issuer_protocol=mock_issuer_protocol,
                                            token_path="/fake/path")

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        with pytest.raises(AuthException, match=f"Token fetch failed, Error was: 404 - test reason test text"):
            authenticator.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=authenticator.token_request_data
        )

    @mock.patch('zepben.auth.authenticator.requests.post', side_effect=lambda *args, **kwargs: MockResponse(None, 200, "test reason", "test text"))
    def test_fetch_token_throws_exception_on_missing_json(self, mock_post):
        authenticator = ZepbenAuthenticator(audience=mock_audience, issuer_domain=mock_auth0_issuer_domain, issuer_protocol=mock_issuer_protocol,
                                            token_path="/fake/path")

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        with pytest.raises(AuthException, match=f'Response did not contain expected JSON - response was: test text'):
            authenticator.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=authenticator.token_request_data
        )

    @mock.patch('zepben.auth.authenticator.requests.post',
                side_effect=lambda *args, **kwargs: MockResponse({'error': 'fail', 'error_description': 'test error description'}, 200))
    def test_fetch_token_throws_exception_on_error_response(self, mock_post):
        authenticator = ZepbenAuthenticator(audience=mock_audience, issuer_domain=mock_auth0_issuer_domain, issuer_protocol=mock_issuer_protocol,
                                            token_path="/fake/path")

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        with pytest.raises(AuthException, match=f'fail - test error description'):
            authenticator.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=authenticator.token_request_data
        )

    @mock.patch('zepben.auth.authenticator.requests.post',
                side_effect=lambda *args, **kwargs: MockResponse({'test': 'fail'}, 200))
    def test_fetch_token_throws_exception_on_missing_access_token(self, mock_post):
        authenticator = ZepbenAuthenticator(audience=mock_audience, issuer_domain=mock_auth0_issuer_domain, issuer_protocol=mock_issuer_protocol,
                                            token_path="/fake/path")

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        with pytest.raises(AuthException, match="Access Token absent in token response - Response was: {'test': 'fail'}"):
            authenticator.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=authenticator.token_request_data
        )

    @mock.patch('zepben.auth.authenticator.requests.post', side_effect=lambda *args, **kwargs: MockResponse(
        {"access_token": TOKEN, "refresh_token": mock_refresh_token, "token_type": "Bearer"}, 200))
    def test_fetch_token_successful_using_refresh(self, mock_post):
        authenticator = ZepbenAuthenticator(audience=mock_audience, issuer_domain=mock_auth0_issuer_domain, issuer_protocol=mock_issuer_protocol,
                                            token_path="/fake/path")

        authenticator.refresh_request_data['refresh_token'] = mock_refresh_token
        mock_post.assert_not_called()  # POST request is not made before get_token() is called
        authenticator._refresh_token = mock_refresh_token
        assert f"Bearer {TOKEN}" == authenticator.fetch_token()

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/fake/path",
            headers=ANY,
            data=authenticator.refresh_request_data
        )