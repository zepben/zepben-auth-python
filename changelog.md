# Zepben Auth Python
## [0.13.0b1] - UNRELEASED
### Breaking Changes
* None.

### New Features
* None.

### Enhancements
* None.

### Fixes
* None.

## [0.12.1] - 2024-10-02
### Notes
* We now support requests up to v3.0.0 (exclusive)

## [0.12.0] - 2024-09-20
### Breaking Changes
* `ZepbenTokenFetcher` and helper functions have changed signatures, so clients need to update.

### New Features
* Added `AuthProviderConfig` object to handle provider-related configuration.
* Added helper functions to fetch auth configuration from EWB and provider configuration

### Enhancements
* None.

### Fixes
* Fixed `_get_token_response_from_identity` function parameters so that callers pass correct values.

### Notes
* None.

## [0.11.1] - 2024-01-16
### Breaking Changes
* None.

### New Features
* None.

### Enhancements
* None.

### Fixes
* Specify correct tokenPath and refresh token claims.

### Notes
* None.

## [0.11.0] - 2023-09-28
##### Breaking Changes
* None.

##### New Features
* Support Azure Entra ID as an OAuth2 auth provider.
* Support Azure Managed Identities as a token fetching endpoint: `create_token_fetcher_managed_identity`

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
