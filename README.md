# Zepben Auth Library #

This library provides Authentication mechanisms for Zepben SDKs used with Energy Workbench and other Zepben services.

Typically this library will be used by the SDKs to plug into connection mechanisms. It is unlikely that end users will
need to use this library directly.

# Usage #

```python
from zepben.auth import create_token_fetcher

authenticator = create_token_fetcher("https://localhost/auth")

authenticator.token_request_data.update({
    {
        "grant_type": "password",
        "username": "<username>",
        "password": "<password>",
        "scope": "offline_access openid profile email",
        "client_id": "<client_id>"
    }
})
authenticator.refresh_request_data.update({
    "grant_type": "refresh_token",
    "scope": "offline_access openid profile email",
    "client_id": "<client_id>"
})

token = authenticator.fetch_token()
```