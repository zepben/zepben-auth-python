#  Copyright 2022 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
import warnings
from datetime import datetime
from typing import Optional, Union
import jwt
import requests
from dataclassy import dataclass
from urllib3.exceptions import InsecureRequestWarning

from zepben.auth.client.util import construct_url
from zepben.auth.common.auth_exception import AuthException
from zepben.auth.common.auth_method import AuthMethod
from zepben.auth.common.auth_provider import AuthProvider


__all__ = ["ZepbenTokenFetcher", "create_token_fetcher", "get_token_fetcher"]


@dataclass
class ZepbenTokenFetcher(object):
    """
    Fetches access tokens from an authentication provider using the OAuth 2.0 protocol.
    """

    audience: str
    """ Audience to use when requesting tokens """

    issuer_domain: str
    """ The domain of the token issuer. """

    auth_method: AuthMethod = AuthMethod.OAUTH
    """ The authentication method used by the server """

    issuer_protocol: str = "https"
    """ Protocol of the token issuer. You should not change this unless you are absolutely sure of what you are doing. Setting it to
        anything other than https is a major security risk as tokens will be sent in the clear. """

    token_path: str = "/oauth/token"
    """ Path for requesting token from `issuer_domain`. """

    token_request_data = {}
    """ Data to pass in token requests. """

    refresh_request_data = {}
    """ Data to pass in refresh token requests. """

    verify: Union[bool, str] = True
    """
    Passed through to requests.post(). When this is a boolean, it determines whether or not to verify the HTTPS certificate of the OAUTH service.
    When this is a string, it is used as the filename of the certificate truststore to use when verifying the OAUTH service.
    """

    _access_token = None
    _refresh_token = None
    _token_expiry = datetime.min
    _token_type = None

    def __init__(self):
        self.token_request_data["audience"] = self.audience
        self.refresh_request_data["audience"] = self.audience

    def fetch_token(self, provider: AuthProvider=AuthProvider.AUTH0) -> str:
        """
        Returns a JWT access token and its type in the form of '<type> <3 part JWT>', retrieved from the configured OAuth2 token provider.
        Throws AuthException if an access token request fails.
        """
        if datetime.utcnow() > self._token_expiry:
            # Stored token has expired, try to refresh
            self._access_token = None
            if self._refresh_token:
                self._fetch_token(provider, True)

            if self._access_token is None:
                # If using the refresh token did not work for any reason, self._access_token will still be None.
                # and thus we must try get a fresh access token using credentials instead.
                self._fetch_token(provider)

            # Just to give a friendly error if a token retrieval failed for a case we haven't handled.
            if not self._token_type or not self._access_token:
                raise Exception(
                    f"Token couldn't be retrieved from {construct_url(self.issuer_protocol, self.issuer_domain, self.token_path)} using configuration "
                    f"{self.auth_method}, audience: {self.audience}, token issuer: {self.issuer_domain}"
                )

        return f"{self._token_type} {self._access_token}"

    def _fetch_token(self, provider: AuthProvider, refresh: bool = False):
        if refresh:
            self.refresh_request_data["refresh_token"] = self._refresh_token

        response: requests.Response
        if provider == AuthProvider.AUTH0:
            response = self._fetch_token_auth0(refresh)
        elif provider == AuthProvider.AZURE:
            response = self._fetch_token_azure(refresh)
        else:
            raise UserWarning(f"Unsupported provider type ${provider}")

        if not response.ok:
            raise AuthException(response.status_code, f'Token fetch failed, Error was: {response.reason} {response.text}')

        try:
            data = response.json()
        except ValueError:
            raise AuthException(response.status_code, f'Response did not contain expected JSON - response was: {response.text}')

        try:
            data = response.json()
        except ValueError:
            raise AuthException(response.status_code, f'Response did not contain expected JSON - response was: {response.text}')

        if "error" in data or "access_token" not in data:
            raise AuthException(
                response.status_code,
                f'{data.get("error", "Access Token absent in token response")} - {data.get("error_description", f"Response was: {data}")}'
            )

        self._token_type = data["token_type"]
        self._access_token = data["access_token"]
        self._token_expiry = datetime.fromtimestamp(jwt.decode(self._access_token, options={"verify_signature": False})['exp'])

        if refresh:
            self._refresh_token = data.get("refresh_token", None)


    def _fetch_token_azure(self, refresh: bool = False) -> requests.Response:
        return requests.post(
            construct_url(self.issuer_protocol, self.issuer_domain, self.token_path),
            headers={"content-type": "application/x-www-form-urlencoded"},
            data=self.refresh_request_data if refresh else self.token_request_data,
            verify=self.verify
        )


    def _fetch_token_auth0(self, refresh: bool = False) -> requests.Response:
        return requests.post(
            construct_url(self.issuer_protocol, self.issuer_domain, self.token_path),
            headers={"content-type": "application/json"},
            json=self.refresh_request_data if refresh else self.token_request_data,
            verify=self.verify
        )

def create_token_fetcher(
    conf_address: str,
    verify_conf: Union[bool, str] = True,
    verify_auth: Union[bool, str] = True,
    auth_type_field: str = "authType",
    audience_field: str = "audience",
    issuer_domain_field: str = "issuer"
) -> Optional[ZepbenTokenFetcher]:
    """
    Helper method to fetch auth related configuration from `conf_address` and create a :class:`ZepbenTokenFetcher`

    :param conf_address: The url to retrieve the authentication config from.
    :param verify_conf: Passed through to requests.get() when retrieving the authentication config. When this is a boolean, it determines whether to verify
                        the HTTPS certificate of `conf_address`. When this is a string, it is used as the filename of the certificate truststore to use
                        when verifying `conf_address`.
    :param verify_auth: Passed through to the resulting :class:`ZepbenTokenFetcher`.
    :param auth_type_field: The field name to look up in the JSON response from the conf_address for `token_fetcher.auth_method`.
    :param audience_field: The field name to look up in the JSON response from the conf_address for `token_fetcher.auth_method`.
    :param issuer_domain_field: The field name to look up in the JSON response from the conf_address for `token_fetcher.auth_method`.

    :returns: A :class:`ZepbenTokenFetcher` if the server reported authentication was configured, otherwise None.
    """
    with warnings.catch_warnings():
        if not verify_conf:
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)

        try:
            response = requests.get(conf_address, verify=verify_conf)
        except Exception as e:
            warnings.warn(str(e))
            warnings.warn("If RemoteDisconnected, this process may hang indefinitely.")
            raise ConnectionError("Are you trying to connect to a HTTPS server with HTTP?")
        else:
            if response.ok:
                try:
                    auth_config_json = response.json()
                    auth_method = AuthMethod(auth_config_json[auth_type_field])
                    if auth_method is not AuthMethod.NONE:
                        return ZepbenTokenFetcher(
                            audience=auth_config_json[audience_field],
                            issuer_domain=auth_config_json[issuer_domain_field],
                            auth_method=auth_method,
                            verify=verify_auth
                        )
                except ValueError:
                    raise AuthException(response.status_code, f"Expected JSON response from {conf_address}, but got: {response.text}.")
            else:
                raise AuthException(
                    response.status_code,
                    f"{conf_address} responded with: {response.reason} {response.text}"
                )

    return None


def get_token_fetcher(audience: str, issuer_domain: str, client_id: str, username: str, password: str) -> ZepbenTokenFetcher:
    """
    Create a token fetcher for the given audience and client, using username and password.

    :param audience: The OAuth audience for this client.
    :param issuer_domain: The domain of the issuer - e.g zepben.au.auth0.com
    :param client_id: The client id to use.
    :param username: The user to log in as. Must have access to the provided audience.
    :param password: The corresponding password for the user.
    """
    token_fetcher = ZepbenTokenFetcher(audience=audience, issuer_domain=issuer_domain, auth_method=AuthMethod.OAUTH)
    token_fetcher.token_request_data.update({
        'client_id': client_id,
        'scope': 'offline_access openid profile email0'
    })
    token_fetcher.refresh_request_data.update({
        "grant_type": "refresh_token",
        'client_id': client_id,
        'scope': 'offline_access openid profile email0'
    })
    token_fetcher.token_request_data.update({
        'grant_type': 'password',
        'username': username,
        'password': password
    })

    return token_fetcher
