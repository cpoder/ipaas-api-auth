# ION API client with a service account (`IonApiClient` package)

Goal: call the Infor M3 APIs (ION API) with an OAuth 2 service account, **without ever configuring or handling a
token**. The only configuration is the `.ionapi` file delivered by Infor, or the manual entry of the same values
in the admin UI (*Manual entry* tab).

## What the user sees

- **Admin UI**: `http://localhost:5555/IonApiClient/index.html` (`?lang=fr` for French), IS authentication
  (Administrator / manage).
  - *Configured accesses*: one card per access (tenant, API base URL, token URL, client id, masked service account,
    token state with countdown and source: password / refresh / cache), **Test** and **Delete** buttons.
  - *Add an access*: access name + `.ionapi` file (file picker or pasted content) **or** manual entry (token server
    URL, API base URL, client id / secret, saak / sask, scope); preview of the parsed fields; **Save**. Nothing
    else to enter.
  - *Call ION API*: access, method, relative path (e.g. `/M3/m3api-rest/v2/execute/CRS610MI/GetBasicData?CUNO=C000042`),
    body; the result shows the HTTP status, the token source (cache, password, refresh), a "renewed after 401"
    badge when relevant, the response time and the JSON.
  - *Token journal*: authentications, renewals, retries after 401, errors, configuration changes.
  - *Simulator* (demo): lifetime of the tokens issued by the fake ION API, to show the renewal.
- **For a business flow**: a single service, `ionapi.api:call (alias, method, path, body?, contentType?)` ->
  `status, statusMessage, body, json, tokenSource, retried, elapsedMs, url`.

## How it works

| Service | Role |
|---|---|
| `ionapi.admin:saveAlias` | accepts either `ionapiJson` or the individual fields (`tokenUrl`, `apiBaseUrl`, `clientId`, `clientSecret`, `saak`, `sask`, `scope`); refuses an incomplete configuration; with a file, reads the `.ionapi` (`ti`, `ci`, `cs`, `saak`, `sask`, `iu`, `pu`, `ot`), computes `tokenUrl = pu + ot` and `apiBaseUrl = iu/ti`, stores the configuration (secrets included) in the IS **outbound password store** (encrypted at rest, `pub.security.outboundPasswords`) |
| `ionapi.admin:listAliases` / `deleteAlias` / `testAlias` | listing without secrets + token state + journal; deletion; authentication test with a diagnostic |
| `ionapi.token:get (alias, forceRefresh)` | returns a valid token: cache (store) when not expired, otherwise `refresh_token` grant, otherwise `password` grant (`username = saak`, `password = sask`, `client_id`, `client_secret`); 30 s safety margin (5 s for short-lived tokens); credentials never leave the service (TRY/CATCH with purge) |
| `ionapi.api:call` | `Authorization: Bearer` set automatically; on **401**, new authentication and a single transparent retry (token revoked on the Infor side, key rotation...) |
| `ionapi.store:*` | store access (`WmSecureString`) |
| `ionapi.token:logEvent` | capped journal kept in the store |

Built through the API (`wm/ionapi_build.py`, builder `wm/putnode_builder.py`): 11 flow services, no Java code.

## ION API simulator (demo and tests)

`mock/ion_mock.py` (standard Python, port 8085) reproduces the shape of the Infor URLs:
`POST /DEMO/as/token.oauth2` (`password` and `refresh_token` grants, client id/secret required) and
`GET /DEMO/M3/m3api-rest/v2/execute/CRS610MI/GetBasicData?CUNO=...` protected by Bearer. `POST /admin/ttl?seconds=N`
sets the token lifetime, `POST /admin/revoke` simulates an invalidation on the Infor side. Demo file:
`docs/demo.ionapi`. The simulator runs outside the IS because the Integration Server intercepts every inbound
`Authorization: Bearer` header itself (it takes it for a token of its own OAuth server).

```bash
python3 mock/ion_mock.py 8085 &          # simulator
python3 wm/ionapi_build.py deploy test   # package + end-to-end tests (about 40 s)
```

Covered tests: store, registration from `.ionapi`, token with the service account, call with a cached token,
expiry then silent re-authentication, server-side revocation then transparent retry, wrong secret refused with a
readable message.

## Connecting a real Infor tenant

Drop the `.ionapi` of the service account (type "Backend Service", Password Credentials grant) in the UI:
`pu`/`ot` give `https://mingle-sso.inforcloudsuite.com:443/<TENANT>/as/token.oauth2`, `iu`/`ti` give
`https://mingle-ionapi.inforcloudsuite.com/<TENANT>`. Check the outbound HTTPS of the IS (truststore, proxy if
needed through `proxyAlias` in `ionapi.token:get` / `ionapi.api:call`). If Infor requires a `scope`, add it to the
pasted `.ionapi` (`scope` field) or through `saveAlias`.

## Limits and possible follow-ups

- A single retry on 401; no rate limiting or queue (to add depending on volumes).
- The journal is capped at about 6 KB (the last event is kept beyond that).
- Natural follow-up: generate typed services from the Swagger of an M3 API (`openapi_generate_consumer`) that rely
  on `ionapi.token:get` for authentication, which gives a "connector" experience without CloudStreams.

## Why the `.ionapi` file (and why it is not mandatory)

An Infor service account is not a simple login / password pair. To obtain a token, Infor requires four secrets:
the `client_id` and `client_secret` of the *authorized app* (the OAuth 2 "client" declared in ION API), then the
`saak` and `sask` of the service account itself (they play the role of login / password in the `password` grant).
Three non-secret values come on top: the tenant, the token server URL and the API base URL. When the authorized
app is created in the ION API portal, Infor generates these seven values and delivers them **only** as the
`.ionapi` file; the `client_secret` cannot be read again afterwards.

So the file brings nothing more than the fields of the manual entry: it is a way to avoid retyping seven long
values (and a typo in a secret ends up as an unhelpful `invalid_client`). Both paths lead to exactly the same
encrypted configuration in the IS store.
