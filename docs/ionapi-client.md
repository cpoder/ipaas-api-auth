# Client ION API par compte de service (package `IonApiClient`)

Objectif : appeler les API Infor M3 (ION API) avec un compte de service OAuth 2, **sans jamais
configurer ni manipuler de jeton**. La seule configuration est le fichier `.ionapi` fourni par Infor, ou
la saisie manuelle des mêmes valeurs dans l'interface d'administration (onglet *Saisie manuelle*).

## Ce que voit l'utilisateur

- **Interface d'administration** : `http://localhost:5555/IonApiClient/index.html` (`?lang=en` pour l'anglais),
  authentification IS (Administrator / manage).
  - *Accès configurés* : une carte par accès (tenant, base des API, URL du jeton, client id, compte de service
    masqué, état du jeton avec compte à rebours et source : mot de passe / refresh / cache), boutons **Tester** et
    **Supprimer**.
  - *Ajouter un accès* : nom de l'accès + fichier `.ionapi` (sélecteur de fichier ou contenu collé) **ou** saisie
    manuelle (URL du serveur de jetons, base des API, client id / secret, saak / sask, scope) ; aperçu des
    champs lus ; **Enregistrer**. Rien d'autre à saisir.
  - *Appeler ION API* : accès, méthode, chemin relatif (ex. `/M3/m3api-rest/v2/execute/CRS610MI/GetBasicData?CUNO=C000042`),
    corps ; le résultat montre le code HTTP, la source du jeton (cache, mot de passe, refresh), un badge
    « renouvelé après un 401 » le cas échéant, le temps de réponse et le JSON.
  - *Journal des jetons* : authentifications, renouvellements, nouveaux essais après 401, erreurs, changements de configuration.
  - *Simulateur* (démo) : réglage de la durée de vie des jetons émis par le faux ION API pour montrer le renouvellement.
- **Pour un flow métier** : un seul service, `ionapi.api:call (alias, method, path, body?, contentType?)` →
  `status, statusMessage, body, json, tokenSource, retried, elapsedMs, url`.

## Comment ça marche

| Service | Rôle |
|---|---|
| `ionapi.admin:saveAlias` | accepte soit `ionapiJson`, soit les champs individuels (`tokenUrl`, `apiBaseUrl`, `clientId`, `clientSecret`, `saak`, `sask`, `scope`) ; refuse une configuration incomplète ; avec un fichier, lit le `.ionapi` (`ti`, `ci`, `cs`, `saak`, `sask`, `iu`, `pu`, `ot`), calcule `tokenUrl = pu + ot` et `apiBaseUrl = iu/ti`, enregistre la configuration (secrets compris) dans le **coffre de mots de passe sortants** de l'IS (chiffré au repos, `pub.security.outboundPasswords`) |
| `ionapi.admin:listAliases` / `deleteAlias` / `testAlias` | liste sans les secrets + état des jetons + journal ; suppression ; test d'authentification avec diagnostic |
| `ionapi.token:get (alias, forceRefresh)` | rend un jeton valable : cache (coffre) si non expiré, sinon grant `refresh_token`, sinon grant `password` (`username = saak`, `password = sask`, `client_id`, `client_secret`) ; marge de sécurité 30 s (5 s pour les jetons courts) ; les identifiants ne sortent jamais du service (TRY/CATCH avec purge) |
| `ionapi.api:call` | `Authorization: Bearer` posé automatiquement ; sur **401**, nouvelle authentification et un seul nouvel essai transparent (jeton révoqué côté Infor, rotation de clés…) |
| `ionapi.store:*` | accès au coffre (`WmSecureString`) |
| `ionapi.token:logEvent` | journal borné conservé dans le coffre |

Construit par API (`wm/ionapi_build.py`, constructeur `wm/putnode_builder.py`) : 11 flow services, aucun code Java.

## Simulateur ION API (démo et tests)

`mock/ion_mock.py` (Python standard, port 8085) reproduit la forme des URL Infor :
`POST /DEMO/as/token.oauth2` (grants `password` et `refresh_token`, client id/secret exigés) et
`GET /DEMO/M3/m3api-rest/v2/execute/CRS610MI/GetBasicData?CUNO=…` protégé par Bearer. `POST /admin/ttl?seconds=N`
règle la durée de vie des jetons, `POST /admin/revoke` simule une invalidation côté Infor. Fichier de démo :
`docs/demo.ionapi`. Le simulateur est hors de l'IS parce que l'Integration Server intercepte lui-même tout
`Authorization: Bearer` entrant (il le prend pour un jeton de son propre serveur OAuth).

```bash
python3 mock/ion_mock.py 8085 &          # simulateur
python3 wm/ionapi_build.py deploy test   # package + tests de bout en bout (~40 s)
```

Tests couverts : coffre, enregistrement depuis `.ionapi`, jeton par compte de service, appel avec jeton en cache,
expiration puis ré-authentification silencieuse, révocation côté serveur puis nouvel essai transparent, secret
erroné refusé avec message lisible.

## Brancher un vrai tenant Infor

Déposer le `.ionapi` du compte de service (type « Backend Service », grant Password Credentials) dans l'interface :
`pu`/`ot` donnent `https://mingle-sso.inforcloudsuite.com:443/<TENANT>/as/token.oauth2`, `iu`/`ti` donnent
`https://mingle-ionapi.inforcloudsuite.com/<TENANT>`. Vérifier la sortie HTTPS de l'IS (truststore, proxy
éventuel via `proxyAlias` dans `ionapi.token:get` / `ionapi.api:call`). Si Infor impose un `scope`, le renseigner
dans le `.ionapi` collé (champ `scope`) ou via `saveAlias`.

## Limites et suites possibles

- Un seul nouvel essai sur 401 ; pas de limitation de débit ni de file d'attente (à ajouter selon les volumes).
- Le journal est borné à ~6 Ko (dernier événement conservé au-delà).
- Suite naturelle : générer des services typés depuis le Swagger d'une API M3 (`openapi_generate_consumer`)
  qui s'appuient sur `ionapi.token:get` pour l'authentification, ce qui donne une expérience « connecteur »
  sans CloudStreams.

## Pourquoi le fichier `.ionapi` (et pourquoi il n'est pas obligatoire)

Un compte de service Infor n'est pas un simple couple login / mot de passe. Pour obtenir un jeton, Infor exige
quatre secrets : le `client_id` et le `client_secret` de l'*application autorisée* (le « client » OAuth2 déclaré
dans ION API), puis le `saak` et le `sask` du compte de service lui-même (ils jouent le rôle de login / mot de
passe dans le grant `password`). S'y ajoutent trois valeurs non secrètes : le tenant, l'URL du serveur de jetons
et l'URL de base des API. Lorsqu'on crée l'application autorisée dans le portail ION API, Infor génère ces sept
valeurs et les livre **uniquement** sous la forme du fichier `.ionapi` ; le `client_secret` n'est d'ailleurs
plus consultable ensuite.

Le fichier n'apporte donc rien de plus que les champs de la saisie manuelle : c'est un moyen d'éviter de recopier
sept valeurs longues (et une erreur de frappe sur un secret se traduit par un `invalid_client` peu parlant).
Les deux chemins aboutissent exactement à la même configuration chiffrée dans le coffre de l'IS.
