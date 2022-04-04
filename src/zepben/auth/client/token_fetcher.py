#  Copyright 2022 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
import warnings
from datetime import datetime
from enum import Enum
from typing import Optional
import jwt
import requests
from dataclassy import dataclass
from urllib3.exceptions import InsecureRequestWarning

from zepben.auth.client.util import construct_url


__all__ = ["ZepbenTokenFetcher", "AuthMethod", "AuthException", "create_token_fetcher"]

_AUTH_HEADER_KEY = 'authorization'


class AuthException(Exception):
    pass


class AuthMethod(Enum):
    """
    An enum class that represents the different authentication methods that could be returned from the server's
    ewb/config/auth endpoint.
    """
    @classmethod
    def _missing_(cls, value: str):
        for member in cls:
            if member.value == value.upper():
                return member

    NONE = "NONE"
    SELF = "self"
    AUTH0 = "AUTH0"


@dataclass
class ZepbenTokenFetcher(object):
    audience: str
    """ Audience to use when requesting tokens """

    issuer_domain: str
    """ The domain of the token issuer. """

    auth_method: AuthMethod
    """ The authentication method used by the server """

    verify_certificate: bool = True
    """ Whether to verify the SSL certificate when making requests """

    issuer_protocol: str = "https"
    """ Protocol of the token issuer. You should not change this unless you are absolutely sure of what you are doing. Setting it to
        anything other than https is a major security risk as tokens will be sent in the clear. """

    token_path: str = "/oauth/token"
    """ Path for requesting token from `issuer_domain`. """

    token_request_data = {}
    """ Data to pass in token requests. """

    refresh_request_data = {}
    """ Data to pass in refresh token requests. """

    ca_filename: Optional[str] = None
    """ Filename of certificate authority used to verify the source and integrity of tokens. The requests library will use the certify package for the list of
        trusted certificates if this is None. Ignored if `verify_certificate` is False."""

    _access_token = None
    _refresh_token = None
    _token_expiry = datetime.min
    _token_type = None

    def __init__(self):
        self.token_request_data["audience"] = self.audience
        self.refresh_request_data["audience"] = self.audience

    def fetch_token(self) -> str:
        """
        Returns a JWT access token and its type in the form of '<type> <3 part JWT>', retrieved from the configured OAuth2 token provider.
        Throws AuthException if an access token request fails.
        """
        if datetime.utcnow() > self._token_expiry:
            # Stored token has expired, try to refresh
            self._access_token = None
            if self._refresh_token:
                self._fetch_token_auth0(True)

            if self._access_token is None:
                # If using the refresh token did not work for any reason, self._access_token will still be None.
                # and thus we must try get a fresh access token using credentials instead.
                self._fetch_token_auth0()

            # Just to give a friendly error if a token retrieval failed for a case we haven't handled.
            if not self._token_type or not self._access_token:
                raise AuthException(
                    f"Token couldn't be retrieved from {construct_url(self.issuer_protocol, self.issuer_domain, self.token_path)} using configuration "
                    f"{self.auth_method}, audience: {self.audience}, token issuer: {self.issuer_domain}")

        return f"{self._token_type} {self._access_token}"

    def _fetch_token_auth0(self, use_refresh: bool = False):
        response = requests.post(
            construct_url(self.issuer_protocol, self.issuer_domain, self.token_path),
            headers={"content-type": "application/x-www-form-urlencoded"},
            data=self.refresh_request_data if use_refresh else self.token_request_data,
            verify=self.verify_certificate and (self.ca_filename or True)
        )

        if not response.ok:
            raise AuthException(f'Token fetch failed, Error was: {response.status_code} - {response.reason} {response.text}')

        try:
            data = response.json()
        except ValueError as e:
            raise AuthException(f'Response did not contain expected JSON - response was: {response.text}', e)

        if "error" in data or "access_token" not in data:
            raise AuthException(f'{data.get("error", "Access Token absent in token response")} - {data.get("error_description", f"Response was: {data}")}')

        self._token_type = data["token_type"]
        self._access_token = data["access_token"]
        self._token_expiry = datetime.fromtimestamp(jwt.decode(self._access_token, options={"verify_signature": False})['exp'])
        self._refresh_token = data.get("refresh_token", None)


def create_token_fetcher(conf_address: str, verify_certificates: bool = True, auth_type_field: str = 'authType', audience_field: str = 'audience',
                         issuer_domain_field: str = 'issuer', conf_ca_filename: Optional[str] = None,
                         auth_ca_filename: Optional[str] = None) -> Optional[ZepbenTokenFetcher]:
    """
    Helper method to fetch auth related configuration from `conf_address` and create a :class:`ZepbenTokenFetcher`

    :param conf_address: Location to retrieve authentication configuration from. Must be a HTTP address that returns a JSON response.
    :param verify_certificates: Whether to verify the certificate when making HTTPS requests. Note you should only use a trusted server
        and never set this to False in a production environment.
    :param auth_type_field: The field name to look up in the JSON response from the conf_address for `token_fetcher.auth_method`.
    :param audience_field: The field name to look up in the JSON response from the conf_address for `token_fetcher.auth_method`.
    :param issuer_domain_field: The field name to look up in the JSON response from the conf_address for `token_fetcher.auth_method`.
    :param conf_ca_filename: An optional filename of the certificate authority used to verify configuration response. Ignored if `verify_certificates` is False.
    :param auth_ca_filename: An optional filename of the certificate authority used to verify auth responses. Ignored if `verify_certificates` is False.

    :returns: A :class:`ZepbenTokenFetcher` if the server reported authentication was configured, otherwise None.
    """
    with warnings.catch_warnings():
        if not verify_certificates:
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        try:
            response = requests.get(conf_address, verify=verify_certificates and (conf_ca_filename or True))
        except Exception as e:
            warnings.warn(str(e))
            warnings.warn("If RemoteDisconnected, this process may hang indefinetly.")
            raise ConnectionError("Are you trying to connect to a HTTPS server with HTTP?")
        if response.ok:
            try:
                auth_config_json = response.json()
                auth_method = AuthMethod(auth_config_json[auth_type_field])
                if auth_method is not AuthMethod.NONE:
                    return ZepbenTokenFetcher(
                        audience=auth_config_json[audience_field],
                        issuer_domain=auth_config_json[issuer_domain_field],
                        auth_method=auth_method,
                        verify_certificate=verify_certificates,
                        ca_filename=auth_ca_filename
                    )
            except ValueError as e:
                raise ValueError(f"Expected JSON response from {conf_address}, but got: {response.text}.", e)
        else:
            raise ValueError(f"{conf_address} responded with error: {response.status_code} - {response.reason} {response.text}")
    return None
