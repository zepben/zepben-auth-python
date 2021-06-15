#  Copyright 2020 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

import time
import warnings
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256

import jwt
import requests
from urllib3.exceptions import InsecureRequestWarning
from zepben.auth.util import construct_url


__all__ = ["EasAuthenticator"]


class EasAuthenticator:
    @dataclass
    class ServerConfig:
        """
            A data class that represents the auth config returned from the server's api/config/auth endpoint.
        """


        class AuthMethod(Enum):
            """
            An enum class that represents the different authentication methods that could be returned from the server's
            api/config/auth endpoint.
            """
            NONE = "none"
            SELF = "self"
            AUTH0 = "auth0"


        auth_method: AuthMethod
        audience: str
        issuer_domain: str


    class EasAuthenticationError(Exception):
        def __init__(self, message: str):
            super(Exception, self).__init__(message)

        """
        An exception caused by an unexpected response from the Evolve App Server when trying to authenticate
        """
        pass


    __access_token: str = None
    __refresh_token: str = None
    __server_config: ServerConfig = None
    __host: str
    __port: int
    __username: str
    __password: str
    __client_id: str
    __client_secret: str
    __verify_certificate: bool
    __protocol: str
    __issuer_protocol: str
    __conf_address: str

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        client_id: str,
        client_secret: str = None,
        verify_certificate: bool = True,
        conf_address: str = "/api/config/auth",
        protocol: str = "https",
        issuer_protocol: str = "https"
    ):
        self.__host = host
        self.__port = port
        self.__username = username
        self.__password = password
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__verify_certificate = verify_certificate
        self.__protocol = protocol
        self.__issuer_protocol = issuer_protocol
        self.__conf_address = conf_address

    def __fetch_token_auth0(self) -> str:
        response = requests.post(
            construct_url(
                protocol=self.__issuer_protocol,
                host=self.get_server_config().issuer_domain,
                path="/oauth/token"
            ),
            headers={"content-type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "password",
                "username": self.__username,
                "password": self.__password,
                "audience": self.get_server_config().audience,
                "scope": "offline_access openid profile email",
                "client_id": self.__client_id
            }
        ).json()
        if "error" in response or "access_token" not in response:
            raise self.EasAuthenticationError(
                message="{error} - {error_description}".format(
                    error=response.get("error", "Access Token absent in token response"),
                    error_description=response.get("error_description", response)
                )
            )
        self.__access_token = response["access_token"]
        self.__refresh_token = response["refresh_token"]
        return self.__access_token

    def __fetch_token_auth0_refresh(self) -> str:
        response = requests.post(
            construct_url(
                protocol=self.__issuer_protocol,
                host=self.get_server_config().issuer_domain,
                path="/oauth/token"
            ),
            headers={"content-type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "refresh_token openid profile email",
                "refresh_token": self.__refresh_token,
                "audience": self.get_server_config().audience,
                "scope": "offline_access",
                "client_id": self.__client_id
            }
        ).json()
        if "error" in response or "access_token" not in response:
            raise self.EasAuthenticationError(
                message="{error} - {error_description}".format(
                    error=response.get("error", "Access Token absent in token response"),
                    error_description=response.get("error_description", response)
                )
            )
        self.__access_token = response["access_token"]
        return self.__access_token

    def __fetch_token_self_auth(self) -> str:
        with warnings.catch_warnings():
            if self.__verify_certificate is False:
                warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            response = requests.post(
                construct_url(
                    protocol=self.__issuer_protocol,
                    host=self.get_server_config().issuer_domain,
                    port=self.__port,
                    path="/oauth/token"
                ),
                headers={"content-type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "password",
                    "username": self.__username,
                    "password": sha256(self.__password.encode("utf-8")).hexdigest(),
                    "audience": self.get_server_config().audience,
                    "scope": "trusted",
                    "client_id": self.__client_id,
                    "client_secret": self.__client_secret
                },
                verify=self.__verify_certificate
            ).json()
            if "error" in response or "access_token" not in response:
                raise self.EasAuthenticationError(
                    message=response["error_description"] if "error_description" in response else response)
            self.__access_token = response["access_token"]
        return self.__access_token

    def get_token(self) -> str:
        if self.__access_token is not None:
            decoded = jwt.decode(jwt=self.__access_token, options={"verify_signature": False})
            if time.time() > decoded["exp"]:
                # Stored token has expired, need to refresh
                if self.__refresh_token is not None:
                    self.__access_token = {
                        self.ServerConfig.AuthMethod.AUTH0: self.__fetch_token_auth0_refresh,
                        self.ServerConfig.AuthMethod.SELF: lambda: None,
                        self.ServerConfig.AuthMethod.NONE: lambda: None
                    }[self.get_server_config().auth_method]()
                else:
                    self.__access_token = None
                if self.__access_token is None:
                    # If using the refresh token did not work for any reason, self.__access_token will now be None.
                    # Re-run this method to get a fresh access token using user credentials instead.
                    return self.get_token()
                return self.__access_token
            else:
                # Stored token is not expired
                return self.__access_token
        self.__access_token = {
            self.ServerConfig.AuthMethod.AUTH0: self.__fetch_token_auth0,
            self.ServerConfig.AuthMethod.SELF: self.__fetch_token_self_auth,
            self.ServerConfig.AuthMethod.NONE: lambda: None
        }[self.get_server_config().auth_method]()
        return self.__access_token

    def get_server_config(self):
        if self.__server_config is not None:
            return self.__server_config
        with warnings.catch_warnings():
            if self.__verify_certificate is False:
                warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            auth_config_json = requests.get(
                construct_url(
                    protocol=self.__protocol,
                    host=self.__host,
                    port=self.__port,
                    path=self.__conf_address
                ),
                verify=self.__verify_certificate
            ).json()
            self.__server_config = self.ServerConfig(
                auth_method=self.ServerConfig.AuthMethod(auth_config_json['configType']),
                audience=auth_config_json['audience'],
                issuer_domain=auth_config_json['issuerDomain']
            )
        return self.__server_config
