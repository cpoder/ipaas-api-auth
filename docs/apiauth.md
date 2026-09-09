# ApiAuth : authentification d'API universelle sur webMethods Integration Server

Package `ApiAuth` (17 flow services, construits par putNode via `wm/apiauth_build.py`) : un **profil d'accès** décrit
comment s'authentifier auprès d'une API ; le flow métier n'appelle qu'un seul service et ne voit jamais de secret
ni de jeton. Le package obtient les jetons, les met en cache (chiffrés), les renouvelle avant expiration, se
ré-authentifie après un 401 et journalise chaque événement. Interface d'administration :
`http://localhost:5555/ApiAuth/index.html` (`?lang=en` pour l'anglais). Généralise le package `IonApiClient`
(Infor ION API devient un simple modèle « grant password »).

## Types de profil

| Type | Ce que le package envoie | Champs |
|---|---|---|
| `none` | rien | `baseUrl` |
| `basic` | `Authorization: Basic base64(user:password)` | `username`, `password` |
| `apikey` | en-tête (`X-API-Key` par défaut) ou paramètre de requête | `keyName`, `keyValue`, `keyIn` (header / query), `keyPrefix` |
| `bearer` | jeton statique (jeton d'accès personnel, clé longue durée) | `token`, `headerName` (Authorization), `prefix` (Bearer) |
| `oauth2` | `Authorization: <token_type> <access_token>` géré automatiquement | `grant`, `tokenUrl`, `clientId`, `clientSecret`, `clientAuth` (body / basic), `scope`, `audience`, `resource`, `extraParams` |

Grants OAuth 2 :

| Grant | Champs supplémentaires | Cas typiques |
|---|---|---|
| `client_credentials` | | Entra ID (Graph), SAP BTP, Auth0, Okta, Salesforce |
| `password` | `username`, `password` | Infor ION API (saak / sask), serveurs anciens |
| `refresh_token` | `refreshToken` (fourni une fois, rotation gérée) | jeton longue durée obtenu ailleurs |
| `authorization_code` | `authUrl`, `redirectUri`, `pkce` (S256 par défaut), `authExtra` | consentement utilisateur (Google, HubSpot, Xero, QuickBooks…) via le bouton **Connecter** |
| `jwt_bearer` | `keyStoreAlias`, `keyAlias`, `jwtAlgorithm`, `jwtIssuer`, `jwtSubject`, `jwtAudience`, `jwtClaims` | comptes de service Google, Salesforce JWT, Box, Adobe (RFC 7523) |

Options communes : `proxyAlias`, `keyStoreAlias` / `keyAlias` (mTLS, certificat client du keystore IS), `trustStore`,
`testPath` (GET de vérification du bouton Tester).

## Services

| Service | Rôle |
|---|---|
| `apiauth.api:call (alias, method, path, body?, contentType?, headers?)` | **le seul service à appeler depuis un flow** ; rend `status`, `body`, `json`, `authType`, `source`, `retried`, `elapsedMs`, `url` |
| `apiauth.credentials:get (alias, forceRefresh?)` | dispatcher : en-tête ou paramètre de requête à ajouter, selon le type ; pour un client HTTP maison |
| `apiauth.oauth:token` | jeton OAuth 2 : cache chiffré → refresh token → grant principal ; marge de sécurité 30 s (5 s pour les jetons courts) ; les identifiants sont purgés du pipeline même en cas d'erreur |
| `apiauth.oauth:tokenRequest` | POST form-urlencoded vers le serveur de jetons, client dans le corps ou en Basic (RFC 6749 §2.3.1), proxy / mTLS |
| `apiauth.oauth:storeToken` | échéance calculée localement, mémorisation chiffrée, journal |
| `apiauth.oauth:authorizeUrl` / `callback` | authorization code + PKCE S256 : URL de consentement, puis point de retour du navigateur (échange du code, page qui se ferme seule) |
| `apiauth.admin:saveProfile / deleteProfile / listProfiles / testProfile / disconnect` | administration ; `listProfiles` ne rend jamais les secrets (indicateurs `has_*`) ; en modification, un secret absent conserve la valeur du coffre |
| `apiauth.store:*`, `apiauth.log:event` | coffre de mots de passe sortants de l'IS (`WmSecureString`, chiffré au repos) et journal borné |

Le mécanisme de renouvellement est le même quel que soit le grant : jeton en cache encore valable → réutilisé ;
expiré → refresh token si le serveur en a fourni un ; sinon grant principal ; sur 401 malgré un jeton jugé valable
(révocation côté serveur) → ré-authentification et un seul nouvel essai transparent. Pour `refresh_token` et
`authorization_code`, si le refresh token n'est plus accepté, l'erreur dit explicitement qu'il faut reconnecter.

## Interface d'administration

Modèles qui pré-remplissent le formulaire : Infor ION API (dépôt du `.ionapi`), Microsoft Entra ID, Salesforce
(client credentials ou JWT), compte de service Google (JWT), SAP BTP, Auth0, Okta, GitHub (jeton personnel),
fournisseur générique avec consentement, et neuf profils prêts à l'emploi contre le simulateur local. Chaque carte
montre l'état du jeton en temps réel (valable / expiré / non connecté, source, refresh token présent) et propose
Tester, Connecter (authorization code), Modifier, Oublier le jeton, Supprimer. Le panneau d'appel exécute
`apiauth.api:call` et affiche les badges HTTP, type, source du jeton, nouvel essai après 401 et durée.

## Simulateur

`mock/auth_mock.py` (port 8086, sans dépendance) : serveur d'autorisation avec les cinq grants, page de consentement,
PKCE, rotation des refresh tokens, vérification de la signature des assertions JWT avec le certificat de la clé IS
(`mock/is_cert.pem`, exporté par `deploy.sh apiauth`), et API protégées en Bearer, Basic, clé d'API (en-tête ou
requête), jeton statique ou sans authentification. `POST /admin/ttl?seconds=N` raccourcit la durée de vie des jetons,
`POST /admin/revoke` les invalide tous : c'est ce qui permet de montrer le renouvellement et le nouvel essai en direct.

`./deploy.sh apiauth` lance le simulateur, déploie le package, exécute la suite de tests (`TESTS OK` attendu :
cinq types, cinq grants, expiration, révocation, rotation, PKCE de bout en bout, erreurs lisibles, aucun secret dans
les sorties) et publie l'interface.

## Vers une vraie API

Créer le profil depuis un modèle, vérifier l'accès HTTPS sortant de l'IS (truststore, `proxyAlias`), puis Tester.
Pour `jwt_bearer`, la clé privée doit être dans un keystore déclaré dans l'IS (Security > Keystore) ; la clé Google
(fichier JSON) s'importe avec `openssl pkcs12 -export` puis un alias de keystore. Pour `authorization_code`,
déclarer chez le fournisseur le `redirectUri` affiché dans le formulaire (`https://<is>/invoke/apiauth.oauth/callback`).

## Ce que le package ne couvre pas

Signatures de requête (AWS SigV4, HMAC), NTLM / Kerberos (disponibles nativement dans `pub.client:http`),
device code grant. Ce sont des extensions possibles du dispatcher `apiauth.credentials:get`.

## Pièges IS rencontrés en construisant le package (sémantique des étapes MAP)

- Dans une même étape MAP, **copier un record entier puis écrire un de ses enfants remplace le record copié** :
  les en-têtes HTTP disparaissaient. Écrire les enfants avant, puis copier le record seul.
- `appendToDocumentList` garde une **référence** vers le document ajouté : le réutiliser écrase l'entrée précédente ;
  supprimer le document après chaque ajout.
- Copie puis valeur par défaut (`overwrite=false`) sur la même cible dans une même étape : imprévisible ; les faire en
  deux étapes séparées.
- Les copies de la **map d'entrée** d'un INVOKE restent dans le pipeline de l'appelant : purger en sortie, sinon
  les secrets fuient (vérifié par les tests).
- `pub.jwt:generateSignedJWT` n'accepte que le format de date `dd/MM/yyyy HH:mm:ss` pour `expirationTime`.
