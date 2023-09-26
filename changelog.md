# Zepben Auth Python
## [0.11.0] - UNRELEASED
##### Breaking Changes
* None.

##### New Features
* Support Azure Entra ID as an OAuth2 auth provider.

##### Enhancements
* None.

##### Fixes
* None.

##### Notes
* None.

## [0.10.0] - 2023-05-31
##### Breaking Changes
* Public classes and functions are now imported through `zepben.auth` rather than `zepben.auth.client`:
```python
from zepben.auth import ZepbenTokenFetcher, AuthMethod, ...
```
* Renamed `ZepbenTokenFetcher`'s module from `token_fetcher` to `zepben_token_fetcher`.
* Refactored `AuthException` to its own module - `auth_exception` in `zepben.auth.common`.
* Refactored `AuthMethod` to its own module - `auth_method` in `zepben.auth.common`.
* Replaced `verify_certificate(s)` and `(...)ca_filename` parameters with `verify(...)` parameters. These are passed
  through as the `verify` parameter in calls to `requests.get` and `requests.post`.
* Replaced several exceptions with an `AuthException` to specify the status code of the response.

##### New Features
* Create a helper function to fetch an api token for graphql end point

##### Enhancements
* None.

##### Fixes
* None.

##### Notes
* None.
