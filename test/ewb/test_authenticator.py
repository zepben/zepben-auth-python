#  Copyright 2020 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

import random
import string
import time
import unittest
from unittest import mock
from unittest.mock import ANY

import jwt
from zepben.auth import EwbAuthenticator

mock_auth_method = random.choice((
    EwbAuthenticator.ServerConfig.AuthMethod.NONE,
    EwbAuthenticator.ServerConfig.AuthMethod.AUTH0
))
mock_audience = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_auth0_issuer_domain = ''.join(random.choices(string.ascii_lowercase, k=10)) + "auth0"
mock_access_token = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_refresh_token = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_username = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_password = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_client_id = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_client_secret = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_host = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_port = random.randint(80, 9999)
mock_protocol = ''.join(random.choices(string.ascii_lowercase, k=10))
mock_issuer_protocol = ''.join(random.choices(string.ascii_lowercase, k=10))


def eas_authenticator_test_mocked_get_requests(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data


    if args[0] == f"{mock_protocol}://{mock_host}:{mock_port}/ewb/auth":
        return MockResponse({
            "authType": mock_auth_method.value,
            "audience": mock_audience,
            "issuer": mock_auth0_issuer_domain
        }, 200)

    return MockResponse(None, 404)


def eas_authenticator_test_mocked_post_requests(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data


    if args[0] == f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/oauth/token":
        return MockResponse({
            "access_token": mock_access_token,
            "refresh_token": mock_refresh_token
        }, 200)

    return MockResponse(None, 404)


class EwbAuthenticatorTest(unittest.TestCase):

    @mock.patch('zepben.auth.ewb.authenticator.requests.get', side_effect=eas_authenticator_test_mocked_get_requests)
    def test_get_server_config(self, mock_get):
        authenticator = EwbAuthenticator(
            host=mock_host,
            port=mock_port,
            username=mock_username,
            password=mock_password,
            client_id=mock_client_id,
            protocol=mock_protocol,
            issuer_protocol=mock_issuer_protocol
        )

        mock_get.assert_not_called()  # GET request is not made before get_server_config() is called

        server_config = authenticator.get_server_config()

        mock_get.assert_called_once_with(f"{mock_protocol}://{mock_host}:{mock_port}/ewb/auth", verify=ANY)  # Expected GET request
        self.assertEqual(mock_auth_method, server_config.auth_method)
        self.assertEqual(mock_audience, server_config.audience)
        self.assertEqual(mock_auth0_issuer_domain, server_config.issuer_domain)  # Parameters match those in the response

    @mock.patch('zepben.auth.ewb.authenticator.requests.post', side_effect=eas_authenticator_test_mocked_post_requests)
    def test_get_token_with_no_auth(self, mock_post):
        authenticator = EwbAuthenticator(
            host=mock_host,
            port=mock_port,
            username=mock_username,
            password=mock_password,
            client_id=mock_client_id,
            protocol=mock_protocol,
            issuer_protocol=mock_issuer_protocol
        )

        # noinspection PyTypeChecker
        authenticator._EwbAuthenticator__server_config = EwbAuthenticator.ServerConfig(
            auth_method=EwbAuthenticator.ServerConfig.AuthMethod.NONE,
            audience=None,
            issuer_domain=None
        )

        mock_post.assert_not_called()  # POST request is not made before get_token() is called
        self.assertIsNone(authenticator.get_token())  # get_token() returns None
        mock_post.assert_not_called()  # POST request was never made

    @mock.patch('zepben.auth.ewb.authenticator.requests.post', side_effect=eas_authenticator_test_mocked_post_requests)
    def test_get_token_with_auth0_auth(self, mock_post):
        authenticator = EwbAuthenticator(
            host=mock_host,
            port=mock_port,
            username=mock_username,
            password=mock_password,
            client_id=mock_client_id,
            protocol=mock_protocol,
            issuer_protocol=mock_issuer_protocol
        )

        # noinspection PyTypeChecker
        authenticator._EwbAuthenticator__server_config = EwbAuthenticator.ServerConfig(
            auth_method=EwbAuthenticator.ServerConfig.AuthMethod.AUTH0,
            audience=mock_audience,
            issuer_domain=mock_auth0_issuer_domain
        )

        mock_post.assert_not_called()  # POST request is not made before get_token() is called

        self.assertEqual(mock_access_token, authenticator.get_token())  # Token from response payload is returned

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/oauth/token",
            headers=ANY,
            data={
                "grant_type": "password",
                "username": mock_username,
                "password": mock_password,
                "audience": mock_audience,
                "scope": "offline_access",
                "client_id": mock_client_id
            }
        )  # Appropriate-looking password grant request was made to the issuer

    @mock.patch('zepben.auth.ewb.authenticator.requests.post', side_effect=eas_authenticator_test_mocked_post_requests)
    def test_refresh_token_with_auth0_auth(self, mock_post):
        authenticator = EwbAuthenticator(
            host=mock_host,
            port=mock_port,
            username=mock_username,
            password=mock_password,
            client_id=mock_client_id,
            protocol=mock_protocol,
            issuer_protocol=mock_issuer_protocol
        )

        # noinspection PyTypeChecker
        authenticator._EwbAuthenticator__server_config = EwbAuthenticator.ServerConfig(
            auth_method=EwbAuthenticator.ServerConfig.AuthMethod.AUTH0,
            audience=mock_audience,
            issuer_domain=mock_auth0_issuer_domain
        )

        authenticator._EwbAuthenticator__access_token = jwt.encode({"exp": time.time() - 1000}, "key")  # Expired JWT
        authenticator._EwbAuthenticator__refresh_token = mock_refresh_token

        mock_post.assert_not_called()  # POST request is not mad before get_token() is called

        self.assertEqual(mock_access_token, authenticator.get_token())  # Token from response payload is returned

        mock_post.assert_called_once_with(
            f"{mock_issuer_protocol}://{mock_auth0_issuer_domain}/oauth/token",
            headers=ANY,
            data={
                "grant_type": "refresh_token",
                "refresh_token": mock_refresh_token,
                "audience": mock_audience,
                "scope": "offline_access",
                "client_id": mock_client_id
            }
        )  # Appropriate-looking refresh_token grant request was made to the issuer


if __name__ == '__main__':
    unittest.main()
