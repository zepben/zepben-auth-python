##### Breaking Changes
* Public classes and functions are now imported through `zepben.auth` rather than `zepben.auth.client`:
```python
from zepben.auth import ZepbenTokenFetcher, AuthMethod, StatusCode, ...
```
* Renamed `ZepbenTokenFetcher`'s module from `token_fetcher` to `zepben_token_fetcher`.
* Refactored `AuthException` to its own module - `auth_exception` in `zepben.auth.common`.
* Refactored `AuthMethod` to its own module - `auth_method` in `zepben.auth.common`.
* Replaced `verify_certificate(s)` and `(...)ca_filename` parameters with `verify(...)` parameters. These are passed
  through as the `verify` parameter in calls to `requests.get` and `requests.post`.
* Replaced several exceptions with an `AuthException` to specify the status code of the response.

##### New Features
* Added enum for gRPC status codes: `StatusCode` in `zepben.auth.common.status_code`.

##### Enhancements
* None.

##### Fixes
* None.

##### Notes
* None.