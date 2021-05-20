import warnings
from enum import Enum
from hashlib import sha256

import requests
from urllib3.exceptions import InsecureRequestWarning


class EwbAuthenticator:
    class AuthMethod(Enum):
        """
        An enum class that represents the different authentication methods that could be returned from the server's
        api/config/auth endpoint.
        """
        NONE = "NONE"
        AUTH0 = "AUTH0"

    class EwbAuthenticationError(Exception):
        def __init__(self, message: str):
            super(Exception, self).__init__(message)

        """
        An exception caused by an unexpected response from the Evolve App Server when trying to authenticate
        """
        pass

    __access_token: str
    __auth_method: AuthMethod = None
    __host: str
    __port: int
    __username: str
    __password: str
    __client_id: str
    __client_secret: str
    __auth0_audience: str
    __auth0_domain: str
    __verify_certificate: bool

    def __init__(
            self,
            host: str,
            port: int,
            username: str,
            password: str,
            client_id: str,
            client_secret: str = None,
            auth0_audience: str = None,
            auth0_domain: str = None,
            verify_certificate: bool = True
    ):
        self.__host = host
        self.__port = port
        self.__username = username
        self.__password = password
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__auth0_audience = auth0_audience
        self.__auth0_domain = auth0_domain
        self.__verify_certificate = verify_certificate

    def __fetch_token_auth0(self) -> str:
        response = requests.post(
            "https://{domain}/oauth/token".format(domain=self.__auth0_domain),
            headers={"content-type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "password",
                "username": self.__username,
                "password": self.__password,
                "audience": self.__auth0_audience,
                "scope": "",
                "client_id": self.__client_id
            }
        ).json()
        if "error" in response or "access_token" not in response:
            raise self.EwbAuthenticationError(
                message="{error} - {error_description}".format(
                    error=response.get("error", "Access Token absent in token response"),
                    error_description=response.get("error_description", response)
                )
            )
        self.__access_token = response["access_token"]
        return self.__access_token

    def get_token(self) -> str:
        if self.__access_token is not None:
            return self.__access_token
        self.__access_token = {
            self.AuthMethod.AUTH0: self.__fetch_token_auth0,
            self.AuthMethod.NONE: lambda: None
        }[self.get_auth_method()]()
        return self.__access_token

    def get_auth_method(self) -> AuthMethod:
        if self.__auth_method is not None:
            return self.__auth_method
        with warnings.catch_warnings():
            if self.__verify_certificate is False:
                warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            auth_config_json = requests.get(
                    "{host}:{port}/ewb/auth".format(host=self.__host, port=self.__port),
                    verify=self.__verify_certificate
                ).json()
            self.__auth_method = self.AuthMethod(auth_config_json['authType'])
            self.__auth0_audience = auth_config_json['audience']
            self.__auth0_domain = auth_config_json['issuer']
        return self.__auth_method
