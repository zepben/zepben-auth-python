### v0.7.0

##### Breaking Changes
* Refactored `zepben.auth.authenticator` to `zepben.auth.client.token_fetcher`
  * Renamed `ZepbenAuthenticator` to `ZepbenTokenFetcher`
  * Renamed `create_authenticator` to `create_token_fetcher`

##### New Features
* Added ability to specify a custom CA for `ZepbenTokenFetcher` via filename.
  * It can alternatively be passed in via `create_token_fetcher`.

##### Enhancements
* None.

##### Fixes
* None.

##### Notes
* None.