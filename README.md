# Zepben Auth Library #

This library provides Authentication mechanisms for Zepben SDKs used with Energy Workbench and other Zepben services.

Typically this library will be used by the SDKs to plug into connection mechanisms. It is unlikely that end users will
need to use this library directly.

# Example Usage #

```python
from zepben.auth.client import get_token_fetcher

authenticator = get_token_fetcher(
    issuer="https://login.microsoftonline.com/293784982371c-8797-4168-a5e7-923874928734/v2.0/",
    audience="49875987458e-e217-4c8f-abf6-394875984758",
    client_id="asdaf98798-0584-41c3-b30c-1f9874596da",
    username="",
    password=""
)

authenticator.token_request_data.update({
    'grant_type': 'client_credentials',
    'client_secret': 'W.Tt5KSzX6Q28lksdajflkajsdflkjaslkdjfxx',
    'client_id': 'asdaf98798-0584-41c3-b30c-1f9874596da',
    'scope': '9873498234-e217-4c8f-abf6-9789889987/.default'})
#

print(authenticator.fetch_token())
```
