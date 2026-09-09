# ApiAuth: universal API authentication on webMethods Integration Server

`ApiAuth` package (17 flow services, built with putNode through `wm/apiauth_build.py`): an **access profile**
describes how to authenticate against an API; the business flow calls a single service and never sees a secret
or a token. The package obtains tokens, caches them (encrypted), renews them before expiry, re-authenticates after
a 401 and journals every event. Admin UI: `http://localhost:5555/ApiAuth/index.html` (`?lang=fr` for French).
Generalizes the `IonApiClient` package (Infor ION API becomes a plain "password grant" template).

## Profile types

| Type | What the package sends | Fields |
|---|---|---|
| `none` | nothing | `baseUrl` |
| `basic` | `Authorization: Basic base64(user:password)` | `username`, `password` |
| `apikey` | header (`X-API-Key` by default) or query parameter | `keyName`, `keyValue`, `keyIn` (header / query), `keyPrefix` |
| `bearer` | static token (personal access token, long-lived key) | `token`, `headerName` (Authorization), `prefix` (Bearer) |
| `oauth2` | `Authorization: <token_type> <access_token>` managed automatically | `grant`, `tokenUrl`, `clientId`, `clientSecret`, `clientAuth` (body / basic), `scope`, `audience`, `resource`, `extraParams` |

OAuth 2 grants:

| Grant | Extra fields | Typical cases |
|---|---|---|
| `client_credentials` | | Entra ID (Graph), SAP BTP, Auth0, Okta, Salesforce |
| `password` | `username`, `password` | Infor ION API (saak / sask), legacy servers |
| `refresh_token` | `refreshToken` (provided once, rotation handled) | long-lived token obtained elsewhere |
| `authorization_code` | `authUrl`, `redirectUri`, `pkce` (S256 by default), `authExtra` | user consent (Google, HubSpot, Xero, QuickBooks...) through the **Connect** button |
| `jwt_bearer` | `keyStoreAlias`, `keyAlias`, `jwtAlgorithm`, `jwtIssuer`, `jwtSubject`, `jwtAudience`, `jwtClaims` | Google service accounts, Salesforce JWT, Box, Adobe (RFC 7523) |

Common options: `proxyAlias`, `keyStoreAlias` / `keyAlias` (mTLS, client certificate from the IS keystore),
`trustStore`, `testPath` (verification GET used by the Test button).

## Services

| Service | Role |
|---|---|
| `apiauth.api:call (alias, method, path, body?, contentType?, headers?)` | **the only service to call from a flow**; returns `status`, `body`, `json`, `authType`, `source`, `retried`, `elapsedMs`, `url` |
| `apiauth.credentials:get (alias, forceRefresh?)` | dispatcher: header or query parameter to add, depending on the type; for a custom HTTP client |
| `apiauth.oauth:token` | OAuth 2 token: encrypted cache, then refresh token, then main grant; 30 s safety margin (5 s for short-lived tokens); credentials are purged from the pipeline even on error |
| `apiauth.oauth:tokenRequest` | POST form-urlencoded to the token server, client in the body or as Basic (RFC 6749 section 2.3.1), proxy / mTLS |
| `apiauth.oauth:storeToken` | expiry computed locally, encrypted storage, journal |
| `apiauth.oauth:authorizeUrl` / `callback` | authorization code + PKCE S256: consent URL, then the browser return point (code exchange, page that closes by itself) |
| `apiauth.admin:saveProfile / deleteProfile / listProfiles / testProfile / disconnect` | administration; `listProfiles` never returns secrets (`has_*` flags); on edit, a missing secret keeps the stored value |
| `apiauth.store:*`, `apiauth.log:event` | IS outbound password store (`WmSecureString`, encrypted at rest) and capped journal |

The renewal mechanism is the same whatever the grant: a cached token still valid is reused; expired, the refresh
token is used when the server provided one; otherwise the main grant; on a 401 despite a token considered valid
(server-side revocation), re-authentication and a single transparent retry. For `refresh_token` and
`authorization_code`, when the refresh token is no longer accepted the error says explicitly that a reconnection is
needed.

## Admin UI

Templates that pre-fill the form: Infor ION API (drop the `.ionapi`), Microsoft Entra ID, Salesforce (client
credentials or JWT), Google service account (JWT), SAP BTP, Auth0, Okta, GitHub (personal token), generic provider
with consent, and nine ready-to-use profiles against the local simulator. Each card shows the token state live
(valid / expired / not connected, source, refresh token present) and offers Test, Connect (authorization code),
Edit, Forget token, Delete. The call panel runs `apiauth.api:call` and shows the HTTP, type, token source, retry
after 401 and duration badges.

## Simulator

`mock/auth_mock.py` (port 8086, no dependency): authorization server with the five grants, consent page, PKCE,
refresh token rotation, verification of the JWT assertion signature with the certificate of the IS key
(`mock/is_cert.pem`, exported by `deploy.sh`), and APIs protected by Bearer, Basic, API key (header or query),
static token or no authentication. `POST /admin/ttl?seconds=N` shortens the token lifetime, `POST /admin/revoke`
invalidates every token: this is what shows the renewal and the retry live.

`./deploy.sh` starts the simulator, deploys the package, runs the test suite (`TESTS OK` expected: five types,
five grants, expiry, revocation, rotation, end-to-end PKCE, readable errors, no secret in the outputs) and
publishes the UI.

## Towards a real API

Create the profile from a template, check the outbound HTTPS of the IS (truststore, `proxyAlias`), then Test.
For `jwt_bearer`, the private key must be in a keystore declared in the IS (Security > Keystore); the Google key
(JSON file) is imported with `openssl pkcs12 -export` then a keystore alias. For `authorization_code`, declare at
the provider the `redirectUri` shown in the form (`https://<is>/invoke/apiauth.oauth/callback`).

## What the package does not cover

Request signatures (AWS SigV4, HMAC), NTLM / Kerberos (available natively in `pub.client:http`), device code
grant. These are possible extensions of the `apiauth.credentials:get` dispatcher.
