#!/usr/bin/env python3
"""ApiAuth package: universal API authentication for webMethods Integration Server, without manual token
handling. A profile = an alias + a type; the business flow calls apiauth.api:call(alias, method, path, body).

Profile types                   fields
  none                          baseUrl
  basic                         baseUrl, username, password
  apikey                        baseUrl, keyName, keyValue, keyIn (header|query), keyPrefix
  bearer   (static token)       baseUrl, token, headerName (Authorization), prefix (Bearer)
  oauth2                        baseUrl, grant, tokenUrl, clientId, clientSecret, clientAuth (body|basic), scope, audience, resource
      grant client_credentials
      grant password            + username, password            (Infor ION API: saak / sask)
      grant refresh_token       + refreshToken (provided once)
      grant authorization_code  + authUrl, redirectUri, pkce     (connected from the admin UI)
      grant jwt_bearer          + keyStoreAlias, keyAlias, jwtAlgorithm, jwtIssuer, jwtSubject, jwtAudience, jwtClaims (object)
  common (optional)             proxyAlias, keyStoreAlias/keyAlias (mTLS), trustStore, testPath, extraParams (object), preset

Usage: apiauth_build.py [deploy] [test]
"""
import json, os, sys, time, urllib.request, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcpcli import Mcp
from putnode_builder import *

PKG = "ApiAuth"
DT = "yyyy-MM-dd HH:mm:ss"
DTN = "yyyyMMddHHmmss"
JWT_DT = "dd/MM/yyyy HH:mm:ss"      # the only date format accepted by pub.jwt:generateSignedJWT

# ------------------------------------------------------------------ building blocks
def now_str(target, pattern=DT):
    return invoke("pub.date:getCurrentDateString", inp=[setv("/pattern;1;0", pattern)], out=[copy("/value;1;0", target), delete("/value;1;0", "/pattern;1;0")])

def json_parse(src, target):
    return invoke("pub.json:jsonStringToDocument", inp=[copy(src, "/jsonString;1;0")], out=[copy("/document;2;0", target), delete("/document;2;0", "/jsonString;1;0")])

def json_string(doc, target):
    return invoke("pub.json:documentToJSONString", inp=[copy(doc, "/document;2;0")], out=[copy("/jsonString;1;0", target), delete("/jsonString;1;0", "/document;2;0")])

def store_get(key_expr, target):
    return invoke("apiauth.store:get", inp=[setv("/key;1;0", key_expr, variables=True)], out=[copy("/value;1;0", target), delete("/key;1;0", "/value;1;0")])

def store_set(key_expr, value_path):
    return invoke("apiauth.store:set", inp=[setv("/key;1;0", key_expr, variables=True), copy(value_path, "/value;1;0")], out=[delete("/key;1;0", "/value;1;0")])

def store_remove(key_expr):
    return invoke("apiauth.store:remove", inp=[setv("/key;1;0", key_expr, variables=True)], out=[delete("/key;1;0")])

def log_event(event, detail, alias_src=None):
    inp = [setv("/event;1;0", event, variables=True), setv("/detail;1;0", detail, variables=True)]
    if alias_src: inp.append(copy(alias_src, "/alias;1;0"))
    return invoke("apiauth.log:event", inp=inp, out=[delete("/event;1;0", "/detail;1;0")] + ([delete("/alias;1;0")] if alias_src else []))

def elapsed_ms(t0, target):
    return [invoke("pub.date:elapsedNanoTime", inp=[copy(t0, "/nanoTime;3;0")], out=[copy("/elapsedNanoTime;3;0", "/elNs;3;0"), delete("/elapsedNanoTime;3;0", "/elapsedNanoTimeStr;1;0", "/nanoTime;3;0")]),
            invoke("pub.string:objectToString", inp=[copy("/elNs;3;0", "/object;3;0")], out=[copy("/string;1;0", "/elNsStr;1;0"), delete("/string;1;0", "/object;3;0", "/elNs;3;0")]),
            invoke("pub.math:divideFloats", inp=[copy("/elNsStr;1;0", "/num1;1;0"), setv("/num2;1;0", "1000000"), setv("/precision;1;0", "0")], out=[copy("/value;1;0", "/msF;1;0"), delete("/value;1;0", "/num1;1;0", "/num2;1;0", "/precision;1;0", "/elNsStr;1;0")]),
            invoke("pub.math:roundNumber", inp=[copy("/msF;1;0", "/num;1;0"), setv("/numberOfDigits;1;0", "0")], out=[copy("/roundedNumber;1;0", target), delete("/roundedNumber;1;0", "/num;1;0", "/numberOfDigits;1;0", "/msF;1;0", t0)])]

def t0():
    return invoke("pub.date:currentNanoTime", out=[copy("/nanoTime;3;0", "/t0;3;0"), delete("/nanoTime;3;0")])

HTTP_FIELDS = ("/url;1;0", "/method;1;0", "/data;2;0", "/loadAs;1;0", "/throwExceptionOnHttp401;1;0", "/timeout;1;0", "/header;2;0", "/lines;2;0", "/body;2;0", "/status;1;0",
               "/statusMessage;1;0", "/encodedURL;1;0", "/headers;2;0", "/auth;2;0", "/proxyAlias;1;0", "/keyStoreAlias;1;0", "/keyAlias;1;0", "/trustStore;1;0")
HTTP_CLEAN = delete(*HTTP_FIELDS)

def body_to_string(target):
    return branch("/respBytes", ("$null", []), ("$default", [invoke("pub.string:bytesToString", inp=[copy("/respBytes;3;0", "/bytes;3;0")], out=[copy("/string;1;0", target), delete("/string;1;0", "/bytes;3;0")])]))

def string_replace(src, search, repl, target):
    return invoke("pub.string:replace", inp=[copy(src, "/inString;1;0"), setv("/searchString;1;0", search), setv("/replaceString;1;0", repl), setv("/useRegex;1;0", "false")],
                  out=[copy("/value;1;0", target), delete("/value;1;0", "/inString;1;0", "/searchString;1;0", "/replaceString;1;0", "/useRegex;1;0")])

def url_encode(src, target):
    return invoke("pub.string:URLEncode", inp=[copy(src, "/inString;1;0")], out=[copy("/value;1;0", target), delete("/value;1;0", "/inString;1;0")])

def base64_of_string(src, target):
    """string -> base64 (no line break)."""
    return [invoke("pub.string:stringToBytes", inp=[copy(src, "/string;1;0"), setv("/encoding;1;0", "UTF-8")], out=[copy("/bytes;3;0", "/b64in;3;0"), delete("/bytes;3;0", "/string;1;0", "/encoding;1;0")]),
            invoke("pub.string:base64Encode", inp=[copy("/b64in;3;0", "/bytes;3;0"), setv("/useNewLine;1;0", "false")], out=[copy("/value;1;0", target), delete("/value;1;0", "/bytes;3;0", "/useNewLine;1;0", "/b64in;3;0")])]

def defaulted(src, target, default):
    """copy then default value, in two separate MAP steps (in the same step the result is unpredictable)."""
    return [mapstep(copy(src, target)), mapstep(setv(target, default, overwrite=False))]

def respond(src, content_type="application/json"):
    return invoke("pub.flow:setResponse", inp=[copy(src, "/responseString;1;0"), setv("/contentType;1;0", content_type)], out=[delete("/responseString;1;0", "/contentType;1;0")])

def secs_remaining(start, end, target):
    return invoke("pub.date:calculateDateDifference", inp=[copy(start, "/startDate;1;0"), copy(end, "/endDate;1;0"), setv("/startDatePattern;1;0", DT), setv("/endDatePattern;1;0", DT)],
                  out=[copy("/dateDifferenceSeconds;1;0", target), delete("/dateDifferenceSeconds;1;0", "/dateDifferenceMinutes;1;0", "/dateDifferenceHours;1;0", "/dateDifferenceDays;1;0", "/startDate;1;0", "/endDate;1;0", "/startDatePattern;1;0", "/endDatePattern;1;0")])

def add_seconds(start, secs, target, pattern_out=DT):
    return invoke("pub.date:incrementDate", inp=[copy(start, "/startDate;1;0"), setv("/startDatePattern;1;0", DT), setv("/endDatePattern;1;0", pattern_out), copy(secs, "/addSeconds;1;0")],
                  out=[copy("/endDate;1;0", target), delete("/endDate;1;0", "/startDate;1;0", "/startDatePattern;1;0", "/endDatePattern;1;0", "/addSeconds;1;0")])

def append_doc(list_path, item_path):
    return invoke("pub.list:appendToDocumentList", inp=[copy(list_path, "/toList;2;1"), copy(item_path, "/fromItem;2;0")], out=[copy("/toList;2;1", list_path), delete("/toList;2;1", "/fromItem;2;0")])

def load_profile(fail_from="$parent"):
    return [store_get("apiauth.profile.%alias%", "/cfgJson;1;0"),
            branch("/cfgJson", ("$null", [exit_(fail_from, "FAILURE", "Unknown access profile: %alias%")])),
            json_parse("/cfgJson;1;0", "/cfg;2;0"), mapstep(delete("/cfgJson;1;0"))]

# ------------------------------------------------------------------ apiauth.store (encrypted IS store)
STORE_SET = service("apiauth.store:set", PKG, sig(field("key"), field("value")), sig(), [
    invoke("pub.security.util:createSecureString", inp=[copy("/value;1;0", "/string;1;0")], out=[copy("/secureString;3;0", "/ss;3;0"), delete("/secureString;3;0", "/string;1;0")]),
    quiet(invoke("pub.security.outboundPasswords:removePassword", inp=[setv("/isInternal;1;0", "false")], out=[delete("/result;1;0", "/message;1;0", "/isInternal;1;0")])),
    invoke("pub.security.outboundPasswords:setPassword", inp=[copy("/ss;3;0", "/password;3;0"), setv("/isInternal;1;0", "false")], out=[delete("/password;3;0", "/isInternal;1;0", "/result;1;0", "/message;1;0", "/ss;3;0")]),
], "Writes a value into the IS outbound password store (encrypted at rest).")

STORE_GET = service("apiauth.store:get", PKG, sig(field("key")), sig(field("value")), [
    invoke("pub.security.outboundPasswords:getPassword", inp=[setv("/isInternal;1;0", "false")], out=[copy("/password;3;0", "/ss;3;0"), delete("/password;3;0", "/isInternal;1;0", "/result;1;0", "/message;1;0")]),
    branch("/ss", ("$null", []), ("$default", [invoke("pub.security.util:convertSecureString", inp=[copy("/ss;3;0", "/secureString;3;0"), setv("/returnAs;1;0", "string")], out=[copy("/string;1;0", "/value;1;0"), delete("/string;1;0", "/secureString;3;0", "/returnAs;1;0")])])),
    mapstep(delete("/ss;3;0")),
], "Reads a value from the store (value absent when the key does not exist).")

STORE_REMOVE = service("apiauth.store:remove", PKG, sig(field("key")), sig(), [
    quiet(invoke("pub.security.outboundPasswords:removePassword", inp=[setv("/isInternal;1;0", "false")], out=[delete("/isInternal;1;0", "/result;1;0", "/message;1;0")])),
], "Removes a key from the store (silent when absent).")

STORE_LIST = service("apiauth.store:list", PKG, sig(), sig(field("keys", "record", 1)), [
    invoke("pub.security.outboundPasswords:listKeys", inp=[setv("/isInternal;1;0", "false")], out=[delete("/isInternal;1;0", "/name;1;0")]),
], "Lists the store keys.")

# ------------------------------------------------------------------ apiauth.log:event
LOG_EVENT = service("apiauth.log:event", PKG, sig(field("alias"), field("event"), field("detail")), sig(), [
    now_str("/time;1;0"),
    store_get("apiauth.events", "/evJson;1;0"),
    branch("/evJson", ("$null", []), ("$default", [json_parse("/evJson;1;0", "/journal;2;0")])),
    mapstep(copy("/time;1;0", "/ev;2;0/time;1;0"), copy("/alias;1;0", "/ev;2;0/alias;1;0"), copy("/event;1;0", "/ev;2;0/event;1;0"), copy("/detail;1;0", "/ev;2;0/detail;1;0")),
    append_doc("/journal;2;0/events;2;1", "/ev;2;0"),
    json_string("/journal;2;0", "/newJson;1;0"),
    invoke("pub.string:length", inp=[copy("/newJson;1;0", "/inString;1;0")], out=[copy("/value;1;0", "/len;1;0"), delete("/value;1;0", "/inString;1;0")]),
    branch_expr(("%len% > 20000", [mapstep(delete("/journal;2;0", "/newJson;1;0")), append_doc("/journal;2;0/events;2;1", "/ev;2;0"), json_string("/journal;2;0", "/newJson;1;0")]), comment="journal capped at 20 KB"),
    store_set("apiauth.events", "/newJson;1;0"),
    mapstep(delete("/time;1;0", "/evJson;1;0", "/journal;2;0", "/ev;2;0", "/newJson;1;0", "/len;1;0", "/event;1;0", "/detail;1;0")),
], "Authentication event journal (tokens obtained, renewed, refused, configuration) kept in the store.")

# ------------------------------------------------------------------ apiauth.oauth:tokenRequest
def http_token(basic):
    inp = [copy("/tokenUrl;1;0", "/url;1;0"), setv("/method;1;0", "post"), setv("/loadAs;1;0", "bytes"), setv("/throwExceptionOnHttp401;1;0", "false"), setv("/timeout;1;0", "20000"),
           copy("/args;2;0", "/data;2;0/args;2;0"), setv("/headers;2;0/Accept;1;0", "application/json"),
           copy("/proxyAlias;1;0", "/proxyAlias;1;0"), copy("/keyStoreAlias;1;0", "/keyStoreAlias;1;0"), copy("/keyAlias;1;0", "/keyAlias;1;0"), copy("/trustStore;1;0", "/trustStore;1;0")]
    inp = [i for i in inp if not (i["type"] == "MAPCOPY" and i["from"] == i["to"])]   # fields already in the pipeline are passed through as they are
    pre = []
    if basic:
        inp += [setv("/auth;2;0/type;1;0", "basic"), copy("/clientId;1;0", "/auth;2;0/user;1;0"), copy("/clientSecret;1;0", "/auth;2;0/pass;1;0")]
    else:
        pre = [mapstep(copy("/clientId;1;0", "/args;2;0/client_id;1;0"), copy("/clientSecret;1;0", "/args;2;0/client_secret;1;0"), comment="client in the body (added before the record copy: writing a child after a record copy replaces the record)")]
    return pre + [invoke("pub.client:http", inp=inp, out=[copy("/header;2;0/status;1;0", "/httpStatus;1;0"), copy("/body;2;0/bytes;3;0", "/respBytes;3;0"), HTTP_CLEAN],
                  comment="client authenticated " + ("with a Basic header (RFC 6749 section 2.3.1)" if basic else "in the body (client_id / client_secret)"))]

TOKEN_REQUEST = service("apiauth.oauth:tokenRequest", PKG,
    sig(field("tokenUrl"), field("args", "record"), field("clientId"), field("clientSecret"), field("clientAuth"), field("proxyAlias"), field("keyStoreAlias"), field("keyAlias"), field("trustStore")),
    sig(field("httpStatus"), field("respJson")), [
    branch("/clientAuth", ("basic", http_token(True)), ("$default", http_token(False)), comment="client authentication method"),
    body_to_string("/respJson;1;0"),
    mapstep(delete("/respBytes;3;0", "/args;2;0", "/clientSecret;1;0", "/clientId;1;0", "/tokenUrl;1;0", "/clientAuth;1;0", "/proxyAlias;1;0", "/keyStoreAlias;1;0", "/keyAlias;1;0", "/trustStore;1;0")),
], "POST form-urlencoded to the token server (client in the body or as Basic, optional proxy / mTLS) -> httpStatus, respJson.")

def token_request(args_nodes, comment):
    """args_nodes: MAPSET/MAPCOPY into /args;2;0/...; adds the profile extraParams, calls tokenRequest."""
    return [mapstep(copy("/cfg;2;0/extraParams;2;0", "/args;2;0"), comment="extra parameters of the profile (copied alone: separate step)"), mapstep(*args_nodes, comment=comment),
            invoke("apiauth.oauth:tokenRequest", inp=[copy("/cfg;2;0/tokenUrl;1;0", "/tokenUrl;1;0"), copy("/cfg;2;0/clientId;1;0", "/clientId;1;0"), copy("/cfg;2;0/clientSecret;1;0", "/clientSecret;1;0"), copy("/cfg;2;0/clientAuth;1;0", "/clientAuth;1;0"),
                                                       copy("/cfg;2;0/proxyAlias;1;0", "/proxyAlias;1;0"), copy("/cfg;2;0/keyStoreAlias;1;0", "/keyStoreAlias;1;0"), copy("/cfg;2;0/keyAlias;1;0", "/keyAlias;1;0"), copy("/cfg;2;0/trustStore;1;0", "/trustStore;1;0")],
                   out=[delete("/args;2;0", "/tokenUrl;1;0", "/clientId;1;0", "/clientSecret;1;0", "/clientAuth;1;0", "/proxyAlias;1;0", "/keyStoreAlias;1;0", "/keyAlias;1;0", "/trustStore;1;0")],
                   comment="input-map copies stay in the caller pipeline: purged on output")]

def take_token(source):
    return [json_parse("/respJson;1;0", "/resp;2;0"),
            mapstep(copy("/resp;2;0/access_token;1;0", "/newToken;1;0"), copy("/resp;2;0/refresh_token;1;0", "/newRefresh;1;0"), copy("/resp;2;0/expires_in;3;0", "/expObj;3;0"), copy("/resp;2;0/token_type;1;0", "/tokenType;1;0"),
                    setv("/tokenSource;1;0", source, variables=True), setv("/expiresInRaw;1;0", "3600"), delete("/resp;2;0")),
            mapstep(setv("/tokenType;1;0", "Bearer", overwrite=False)),
            branch("/expObj", ("$null", []), ("$default", [invoke("pub.string:objectToString", inp=[copy("/expObj;3;0", "/object;3;0")], out=[copy("/string;1;0", "/expiresInRaw;1;0"), delete("/string;1;0", "/object;3;0")])]),
                   comment="expires_in: number or string depending on the server, 3600 s by default"),
            mapstep(delete("/expObj;3;0"))]

# ------------------------------------------------------------------ apiauth.oauth:storeToken
STORE_TOKEN = service("apiauth.oauth:storeToken", PKG, sig(field("alias"), field("newToken"), field("newRefresh"), field("expiresInRaw"), field("tokenSource"), field("tokenType")), sig(field("expiresAt"), field("expiresIn")), [
    now_str("/now;1;0"),
    branch_expr(("%expiresInRaw% < 60", [mapstep(setv("/margin;1;0", "5"))]), ("$default", [mapstep(setv("/margin;1;0", "30"))]), comment="safety margin: 30 s, or 5 s for short-lived tokens"),
    invoke("pub.math:subtractInts", inp=[copy("/expiresInRaw;1;0", "/num1;1;0"), copy("/margin;1;0", "/num2;1;0")], out=[copy("/value;1;0", "/expiresIn;1;0"), delete("/value;1;0", "/num1;1;0", "/num2;1;0", "/margin;1;0")]),
    add_seconds("/now;1;0", "/expiresIn;1;0", "/expiresAt;1;0"), add_seconds("/now;1;0", "/expiresIn;1;0", "/expiresAtNum;1;0", DTN),
    mapstep(copy("/newToken;1;0", "/tokState;2;0/access_token;1;0"), copy("/newRefresh;1;0", "/tokState;2;0/refresh_token;1;0"), copy("/expiresAt;1;0", "/tokState;2;0/expiresAt;1;0"), copy("/expiresAtNum;1;0", "/tokState;2;0/expiresAtNum;1;0"),
            copy("/now;1;0", "/tokState;2;0/obtainedAt;1;0"), copy("/tokenSource;1;0", "/tokState;2;0/source;1;0"), copy("/expiresInRaw;1;0", "/tokState;2;0/expiresIn;1;0"), copy("/tokenType;1;0", "/tokState;2;0/token_type;1;0")),
    json_string("/tokState;2;0", "/tokStateJson;1;0"),
    store_set("apiauth.token.%alias%", "/tokStateJson;1;0"),
    log_event("%tokenSource%", "token obtained, valid for %expiresInRaw% s"),
    mapstep(delete("/now;1;0", "/expiresAtNum;1;0", "/tokState;2;0", "/tokStateJson;1;0", "/newToken;1;0", "/newRefresh;1;0", "/expiresInRaw;1;0", "/tokenSource;1;0", "/tokenType;1;0")),
], "Stores a token (encrypted) with its locally computed expiry, and journals it.")

# ------------------------------------------------------------------ apiauth.oauth:token
def jwt_assertion():
    """JWT assertion signed by a key of the IS keystore (Google, Salesforce, Box, Adobe...)."""
    return [now_str("/jwtNow;1;0"), mapstep(setv("/jwtTtl;1;0", "300")), add_seconds("/jwtNow;1;0", "/jwtTtl;1;0", "/jwtExp;1;0", JWT_DT),
            mapstep(copy("/cfg;2;0/jwtAudience;1;0", "/audItem;1;0"), copy("/cfg;2;0/tokenUrl;1;0", "/audDefault;1;0"), comment="audience: the profile one, otherwise the token server URL"),
            branch("/audItem", ("$null", [mapstep(copy("/audDefault;1;0", "/audItem;1;0"))])),
            invoke("pub.list:appendToStringList", inp=[copy("/audItem;1;0", "/fromItem;1;0")], out=[copy("/toList;1;1", "/audience;1;1"), delete("/toList;1;1", "/fromItem;1;0")]),
            branch("/cfg/jwtClaims", ("$null", []), ("$default", [
                invoke("pub.document:documentToDocumentList", inp=[copy("/cfg;2;0/jwtClaims;2;0", "/document;2;0"), setv("/name;1;0", "name"), setv("/value;1;0", "value")], out=[copy("/documentList;2;1", "/claimList;2;1"), delete("/documentList;2;1", "/document;2;0", "/name;1;0", "/value;1;0")]),
                loop("/claimList", None,
                     mapstep(copy("/claimList;2;0/name;1;0", "/cc;2;0/name;1;0"), setv("/cc;2;0/type;1;0", "String")),
                     invoke("pub.list:appendToStringList", inp=[copy("/claimList;2;0/value;1;0", "/fromItem;1;0")], out=[copy("/toList;1;1", "/cc;2;0/value;1;1"), delete("/toList;1;1", "/fromItem;1;0")]),
                     append_doc("/customClaims;2;1", "/cc;2;0"), mapstep(delete("/cc;2;0"))),
                mapstep(delete("/claimList;2;1"))]), comment="extra claims from the profile (e.g. scope for Google)"),
            *defaulted("/cfg;2;0/jwtAlgorithm;1;0", "/jwtAlg;1;0", "RS256"),
            mapstep(copy("/cfg;2;0/clientId;1;0", "/jwtIss;1;0"), comment="issuer: the profile one, otherwise the client id"),
            branch("/cfg/jwtIssuer", ("$null", []), ("$default", [mapstep(copy("/cfg;2;0/jwtIssuer;1;0", "/jwtIss;1;0"))])),
            invoke("pub.jwt:generateSignedJWT", inp=[copy("/jwtAlg;1;0", "/algorithm;1;0"), copy("/cfg;2;0/keyStoreAlias;1;0", "/keyStoreAlias;1;0"), copy("/cfg;2;0/keyAlias;1;0", "/keyAlias;1;0"),
                                                  copy("/jwtIss;1;0", "/issuer;1;0"), copy("/cfg;2;0/jwtSubject;1;0", "/subject;1;0"),
                                                  copy("/jwtExp;1;0", "/expirationTime;1;0"), setv("/addIssuedAtTimeClaim;1;0", "true"), setv("/allowWeakKey;1;0", "true")],
                   out=[copy("/jwt;1;0", "/assertion;1;0"), delete("/jwt;1;0", "/algorithm;1;0", "/keyStoreAlias;1;0", "/keyAlias;1;0", "/issuer;1;0", "/subject;1;0", "/audience;1;1", "/expirationTime;1;0", "/addIssuedAtTimeClaim;1;0", "/allowWeakKey;1;0", "/customClaims;2;1")],
                   comment="RS256 signature with the private key of the IS keystore: the key never leaves the server"),
            mapstep(delete("/jwtNow;1;0", "/jwtTtl;1;0", "/jwtExp;1;0", "/audItem;1;0", "/audDefault;1;0", "/jwtAlg;1;0", "/jwtIss;1;0"))]

TOKEN = service("apiauth.oauth:token", PKG, sig(field("alias"), field("forceRefresh")), sig(field("accessToken"), field("tokenType"), field("tokenSource"), field("expiresAt"), field("expiresIn")), [
    *try_catch([
    *load_profile(),
    mapstep(setv("/valid;1;0", "false"), setv("/forceRefresh;1;0", "false", overwrite=False)),
    now_str("/now;1;0"), now_str("/nowNum;1;0", DTN),
    store_get("apiauth.token.%alias%", "/tokJson;1;0"),
    branch("/tokJson", ("$null", []), ("$default", [
        json_parse("/tokJson;1;0", "/tok;2;0"),
        branch_expr(("%forceRefresh% != \"true\" && %tok/expiresAtNum% > %nowNum%", [mapstep(setv("/valid;1;0", "true")), secs_remaining("/now;1;0", "/tok;2;0/expiresAt;1;0", "/remaining;1;0")]), comment="cached token still valid?")])),
    branch("/valid",
        ("true", [mapstep(copy("/tok;2;0/access_token;1;0", "/accessToken;1;0"), copy("/tok;2;0/token_type;1;0", "/tokenType;1;0"), copy("/tok;2;0/expiresAt;1;0", "/expiresAt;1;0"), copy("/remaining;1;0", "/expiresIn;1;0"), setv("/tokenSource;1;0", "cache"), comment="cache")]),
        ("$default", [
            mapstep(copy("/cfg;2;0/refreshToken;1;0", "/rtok;1;0"), comment="known refresh token: the one of the last token, otherwise the one provided in the profile"),
            branch("/tok/refresh_token", ("$null", []), ("$default", [mapstep(copy("/tok;2;0/refresh_token;1;0", "/rtok;1;0"))])),
            branch("/rtok", ("$null", []), ("$default", [
                mapstep(copy("/rtok;1;0", "/newRefresh;1;0")),
                quiet(*token_request([setv("/args;2;0/grant_type;1;0", "refresh_token"), copy("/rtok;1;0", "/args;2;0/refresh_token;1;0"), copy("/cfg;2;0/scope;1;0", "/args;2;0/scope;1;0")], "refresh_token grant"),
                      branch("/httpStatus", ("200", take_token("refresh")), ("$default", [log_event("refresh-ko", "refresh refused (HTTP %httpStatus%): falling back to the main grant")])),
                      mapstep(delete("/respJson;1;0", "/httpStatus;1;0")), comment="renewal, failure tolerated")])),
            branch("/newToken", ("$null", [
                branch("/cfg/grant",
                    ("client_credentials", token_request([setv("/args;2;0/grant_type;1;0", "client_credentials"), copy("/cfg;2;0/scope;1;0", "/args;2;0/scope;1;0"), copy("/cfg;2;0/audience;1;0", "/args;2;0/audience;1;0"), copy("/cfg;2;0/resource;1;0", "/args;2;0/resource;1;0")], "client_credentials grant")),
                    ("password", token_request([setv("/args;2;0/grant_type;1;0", "password"), copy("/cfg;2;0/username;1;0", "/args;2;0/username;1;0"), copy("/cfg;2;0/password;1;0", "/args;2;0/password;1;0"), copy("/cfg;2;0/scope;1;0", "/args;2;0/scope;1;0"), copy("/cfg;2;0/audience;1;0", "/args;2;0/audience;1;0")], "password grant (service account)")),
                    ("jwt_bearer", [*jwt_assertion(), *token_request([setv("/args;2;0/grant_type;1;0", "urn:ietf:params:oauth:grant-type:jwt-bearer"), copy("/assertion;1;0", "/args;2;0/assertion;1;0"), copy("/cfg;2;0/scope;1;0", "/args;2;0/scope;1;0")], "jwt-bearer grant (RFC 7523)"), mapstep(delete("/assertion;1;0"))]),
                    ("refresh_token", [exit_("$parent", "FAILURE", "No valid refresh token for %alias%: provide a new one in the profile")]),
                    ("authorization_code", [exit_("$parent", "FAILURE", "Connection required for %alias%: use Connect in the admin UI (the refresh token is missing or no longer accepted)")]),
                    ("$default", [exit_("$parent", "FAILURE", "Unknown OAuth 2 grant: %cfg/grant%")]), comment="main grant of the profile"),
                branch("/httpStatus", ("200", take_token("%cfg/grant%")), ("$default", [exit_("$parent", "FAILURE", "Authentication refused by the token server (HTTP %httpStatus%): %respJson%")])),
                mapstep(delete("/respJson;1;0", "/httpStatus;1;0"))]), comment="no token through refresh: main grant"),
            branch("/newToken", ("$null", [exit_("$parent", "FAILURE", "The token server did not return an access_token")])),
            invoke("apiauth.oauth:storeToken", comment="encrypted storage + journal"),
            mapstep(copy("/newToken;1;0", "/accessToken;1;0"), delete("/newToken;1;0", "/newRefresh;1;0", "/expiresInRaw;1;0", "/rtok;1;0")),
        ]), comment="valid cache? otherwise refresh, otherwise main grant"),
    mapstep(delete("/cfg;2;0", "/tok;2;0", "/tokJson;1;0", "/now;1;0", "/nowNum;1;0", "/valid;1;0", "/remaining;1;0", "/forceRefresh;1;0")),
    ], [
        invoke("pub.flow:getLastFailureCaught", out=[copy("/failureMessage;1;0", "/tokenError;1;0"), delete("/failureMessage;1;0", "/failureName;1;0", "/failure;3;0")]),
        mapstep(delete("/cfg;2;0", "/tok;2;0", "/tokJson;1;0", "/cfgJson;1;0", "/now;1;0", "/nowNum;1;0", "/valid;1;0", "/remaining;1;0", "/forceRefresh;1;0", "/newToken;1;0", "/newRefresh;1;0", "/rtok;1;0", "/expiresInRaw;1;0",
                       "/respJson;1;0", "/respBytes;3;0", "/httpStatus;1;0", "/resp;2;0", "/args;2;0", "/assertion;1;0", "/audience;1;1", "/customClaims;2;1"), comment="no secret may remain in the pipeline"),
        exit_("$flow", "FAILURE", "%tokenError%"),
    ]),
], "Valid OAuth 2 token for a profile: encrypted cache, otherwise refresh token, otherwise main grant (client_credentials, password, jwt_bearer). Credentials never leave the service.")

# ------------------------------------------------------------------ apiauth.oauth:authorizeUrl / callback (authorization code + PKCE)
AUTHORIZE_URL = service("apiauth.oauth:authorizeUrl", PKG, sig(field("alias"), field("redirectUri")), sig(field("url"), field("state")), [
    *load_profile("$flow"),
    branch("/cfg/authUrl", ("$null", [exit_("$flow", "FAILURE", "Profile %alias% has no authorization URL (authUrl)")])),
    mapstep(copy("/cfg;2;0/redirectUri;1;0", "/redirectUriCfg;1;0"), comment="redirectUri: the profile one, unless provided as input"),
    branch("/redirectUri", ("$null", [mapstep(copy("/redirectUriCfg;1;0", "/redirectUri;1;0"))])),
    invoke("pub.utils:generateUUID", out=[copy("/UUID;1;0", "/state;1;0"), delete("/UUID;1;0")]),
    invoke("pub.utils:generateUUID", out=[copy("/UUID;1;0", "/v1;1;0"), delete("/UUID;1;0")]), invoke("pub.utils:generateUUID", out=[copy("/UUID;1;0", "/v2;1;0"), delete("/UUID;1;0")]),
    mapstep(setv("/verifier;1;0", "%v1%%v2%", variables=True), delete("/v1;1;0", "/v2;1;0"), comment="PKCE: random code_verifier (72 characters)"),
    invoke("pub.string:stringToBytes", inp=[copy("/verifier;1;0", "/string;1;0"), setv("/encoding;1;0", "UTF-8")], out=[copy("/bytes;3;0", "/vBytes;3;0"), delete("/bytes;3;0", "/string;1;0", "/encoding;1;0")]),
    invoke("pub.security.util:createMessageDigest", inp=[setv("/algorithm;1;0", "SHA-256"), copy("/vBytes;3;0", "/input;3;0")], out=[copy("/output;3;0", "/digest;3;0"), delete("/output;3;0", "/input;3;0", "/algorithm;1;0", "/vBytes;3;0")]),
    invoke("pub.string:base64Encode", inp=[copy("/digest;3;0", "/bytes;3;0"), setv("/useNewLine;1;0", "false")], out=[copy("/value;1;0", "/c1;1;0"), delete("/value;1;0", "/bytes;3;0", "/useNewLine;1;0", "/digest;3;0")]),
    string_replace("/c1;1;0", "+", "-", "/c2;1;0"), string_replace("/c2;1;0", "/", "_", "/c3;1;0"), string_replace("/c3;1;0", "=", "", "/challenge;1;0"),
    mapstep(delete("/c1;1;0", "/c2;1;0", "/c3;1;0"), comment="base64url(SHA-256(verifier)) = code_challenge S256"),
    mapstep(copy("/alias;1;0", "/pk;2;0/alias;1;0"), copy("/verifier;1;0", "/pk;2;0/verifier;1;0"), copy("/redirectUri;1;0", "/pk;2;0/redirectUri;1;0")),
    json_string("/pk;2;0", "/pkJson;1;0"), store_set("apiauth.pkce.%state%", "/pkJson;1;0"),
    url_encode("/cfg;2;0/clientId;1;0", "/eClient;1;0"), url_encode("/redirectUri;1;0", "/eRedirect;1;0"), url_encode("/state;1;0", "/eState;1;0"),
    invoke("pub.string:indexOf", inp=[copy("/cfg;2;0/authUrl;1;0", "/inString;1;0"), setv("/subString;1;0", "?")], out=[copy("/value;1;0", "/qpos;1;0"), delete("/value;1;0", "/inString;1;0", "/subString;1;0")]),
    branch_expr(("%qpos% < 0", [mapstep(setv("/sep;1;0", "?"))]), ("$default", [mapstep(setv("/sep;1;0", "&"))])),
    mapstep(setv("/url;1;0", "%cfg/authUrl%%sep%response_type=code&client_id=%eClient%&redirect_uri=%eRedirect%&state=%eState%", variables=True)),
    branch("/cfg/pkce", ("false", []), ("$default", [mapstep(setv("/url;1;0", "%url%&code_challenge=%challenge%&code_challenge_method=S256", variables=True))]), comment="PKCE enabled unless explicitly disabled"),
    branch("/cfg/scope", ("$null", []), ("$default", [url_encode("/cfg;2;0/scope;1;0", "/eScope;1;0"), mapstep(setv("/url;1;0", "%url%&scope=%eScope%", variables=True), delete("/eScope;1;0"))])),
    branch("/cfg/audience", ("$null", []), ("$default", [url_encode("/cfg;2;0/audience;1;0", "/eAud;1;0"), mapstep(setv("/url;1;0", "%url%&audience=%eAud%", variables=True), delete("/eAud;1;0"))])),
    branch("/cfg/authExtra", ("$null", []), ("$default", [mapstep(setv("/url;1;0", "%url%&%cfg/authExtra%", variables=True))]), comment="raw extra parameters (e.g. access_type=offline&prompt=consent for Google)"),
    mapstep(delete("/cfg;2;0", "/verifier;1;0", "/challenge;1;0", "/pk;2;0", "/pkJson;1;0", "/eClient;1;0", "/eRedirect;1;0", "/eState;1;0", "/qpos;1;0", "/sep;1;0", "/redirectUri;1;0", "/redirectUriCfg;1;0")),
], "Builds the authorization URL (authorization code + PKCE S256) and stores the request state.")

CALLBACK_HTML = ('<!doctype html><meta charset="utf-8"><title>ApiAuth</title><body style="font:16px system-ui;background:#0f1419;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0">'
                 '<div style="text-align:center"><div style="font-size:40px">%icon%</div><h2>%title%</h2><p style="color:#8b98a8">%detail%</p></div>'
                 '<script>try{if(window.opener){window.opener.postMessage({apiauth:"%outcome%",alias:"%alias%"},"*");setTimeout(()=>window.close(),1500);}}catch(e){}</script></body>')

CALLBACK = service("apiauth.oauth:callback", PKG, sig(field("code"), field("state"), field("error"), field("error_description")), sig(), [
    *try_catch([
        branch("/state", ("$null", [exit_("$parent", "FAILURE", "Missing state parameter")])),
        store_get("apiauth.pkce.%state%", "/pkJson;1;0"),
        branch("/pkJson", ("$null", [exit_("$parent", "FAILURE", "Unknown or already used authorization request (state)")])),
        store_remove("apiauth.pkce.%state%"),
        json_parse("/pkJson;1;0", "/pk;2;0"), mapstep(copy("/pk;2;0/alias;1;0", "/alias;1;0")),
        branch("/error", ("$null", []), ("$default", [log_event("error", "authorization refused: %error% %error_description%"), exit_("$parent", "FAILURE", "Authorization refused by the server: %error% %error_description%")])),
        *load_profile(),
        *token_request([setv("/args;2;0/grant_type;1;0", "authorization_code"), copy("/code;1;0", "/args;2;0/code;1;0"), copy("/pk;2;0/redirectUri;1;0", "/args;2;0/redirect_uri;1;0"), copy("/pk;2;0/verifier;1;0", "/args;2;0/code_verifier;1;0")], "exchange of the code for tokens (PKCE)"),
        branch("/httpStatus", ("200", take_token("authorization_code")), ("$default", [exit_("$parent", "FAILURE", "Code exchange refused (HTTP %httpStatus%): %respJson%")])),
        branch("/newToken", ("$null", [exit_("$parent", "FAILURE", "No access_token in the response")])),
        invoke("apiauth.oauth:storeToken", comment="encrypted storage + journal"),
        mapstep(setv("/html;1;0", CALLBACK_HTML.replace("%icon%", "✅").replace("%title%", "Connected").replace("%detail%", "Profile %alias% now has a token (valid for %expiresIn% s) and a refresh token. This window closes by itself.").replace("%outcome%", "connected"), variables=True)),
        respond("/html;1;0", "text/html; charset=utf-8"),
        mapstep(delete("/cfg;2;0", "/pk;2;0", "/pkJson;1;0", "/code;1;0", "/state;1;0", "/newToken;1;0", "/newRefresh;1;0", "/expiresInRaw;1;0", "/respJson;1;0", "/httpStatus;1;0", "/html;1;0", "/expiresAt;1;0", "/expiresIn;1;0", "/alias;1;0")),
    ], [
        invoke("pub.flow:getLastFailureCaught", out=[copy("/failureMessage;1;0", "/cbError;1;0"), delete("/failureMessage;1;0", "/failureName;1;0", "/failure;3;0")]),
        mapstep(setv("/alias;1;0", "?", overwrite=False), setv("/html;1;0", CALLBACK_HTML.replace("%icon%", "⛔").replace("%title%", "Connection failed").replace("%detail%", "%cbError%").replace("%outcome%", "failed"), variables=True)),
        respond("/html;1;0", "text/html; charset=utf-8"),
        mapstep(delete("/cfg;2;0", "/pk;2;0", "/pkJson;1;0", "/code;1;0", "/state;1;0", "/newToken;1;0", "/newRefresh;1;0", "/expiresInRaw;1;0", "/respJson;1;0", "/httpStatus;1;0", "/html;1;0", "/cbError;1;0", "/args;2;0", "/error;1;0", "/error_description;1;0", "/alias;1;0")),
    ]),
], "Browser return point after consent: exchanges the code (PKCE) for tokens, stores them and closes the window.")

# ------------------------------------------------------------------ apiauth.credentials:get (dispatcher)
CREDENTIALS = service("apiauth.credentials:get", PKG, sig(field("alias"), field("forceRefresh")),
    sig(field("type"), field("authHeaderName"), field("authHeaderValue"), field("queryName"), field("queryValue"), field("baseUrl"), field("source"), field("expiresIn"), field("proxyAlias"), field("keyStoreAlias"), field("keyAlias"), field("trustStore")), [
    *load_profile("$flow"),
    mapstep(copy("/cfg;2;0/type;1;0", "/type;1;0"), copy("/cfg;2;0/baseUrl;1;0", "/baseUrl;1;0"), copy("/cfg;2;0/proxyAlias;1;0", "/proxyAlias;1;0"), copy("/cfg;2;0/trustStore;1;0", "/trustStore;1;0"), setv("/source;1;0", "profile")),
    branch("/cfg/type",
        ("none", []),
        ("basic", [mapstep(setv("/userpass;1;0", "%cfg/username%:%cfg/password%", variables=True)), *base64_of_string("/userpass;1;0", "/b64;1;0"),
                   mapstep(setv("/authHeaderName;1;0", "Authorization"), setv("/authHeaderValue;1;0", "Basic %b64%", variables=True), delete("/userpass;1;0", "/b64;1;0"))]),
        ("apikey", [*defaulted("/cfg;2;0/keyPrefix;1;0", "/prefix;1;0", ""),
                    branch("/cfg/keyIn", ("query", [mapstep(copy("/cfg;2;0/keyName;1;0", "/queryName;1;0"), setv("/queryValue;1;0", "%prefix%%cfg/keyValue%", variables=True))]),
                                         ("$default", [*defaulted("/cfg;2;0/keyName;1;0", "/authHeaderName;1;0", "X-API-Key"), mapstep(setv("/authHeaderValue;1;0", "%prefix%%cfg/keyValue%", variables=True))])),
                    mapstep(delete("/prefix;1;0"))]),
        ("bearer", [*defaulted("/cfg;2;0/headerName;1;0", "/authHeaderName;1;0", "Authorization"), *defaulted("/cfg;2;0/prefix;1;0", "/prefix;1;0", "Bearer"),
                    mapstep(setv("/authHeaderValue;1;0", "%prefix% %cfg/token%", variables=True), delete("/prefix;1;0"))]),
        ("oauth2", [invoke("apiauth.oauth:token", out=[copy("/tokenSource;1;0", "/source;1;0"), delete("/tokenSource;1;0", "/expiresAt;1;0")]),
                    *defaulted("/cfg;2;0/headerName;1;0", "/authHeaderName;1;0", "Authorization"),
                    mapstep(setv("/authHeaderValue;1;0", "%tokenType% %accessToken%", variables=True), delete("/accessToken;1;0", "/tokenType;1;0"))]),
        ("$default", [exit_("$flow", "FAILURE", "Unknown profile type: %cfg/type%")]), comment="a single entry point whatever the mechanism"),
    mapstep(copy("/cfg;2;0/keyStoreAlias;1;0", "/keyStoreAlias;1;0"), copy("/cfg;2;0/keyAlias;1;0", "/keyAlias;1;0"), delete("/cfg;2;0", "/forceRefresh;1;0"), comment="optional mTLS (client certificate from the keystore)"),
], "Returns what must be added to a request for a profile: header (Basic, key, static Bearer or managed OAuth 2) or query parameter. The calling flow never sees a raw secret.")

# ------------------------------------------------------------------ apiauth.api:call
def http_api_call(comment):
    return invoke("pub.client:http",
                  inp=[copy("/hdrs;2;0", "/headers;2;0"), copy("/body;1;0", "/data;2;0/string;1;0"), setv("/loadAs;1;0", "bytes"), setv("/throwExceptionOnHttp401;1;0", "false"), setv("/timeout;1;0", "30000")],
                  out=[copy("/header;2;0/status;1;0", "/httpStatus;1;0"), copy("/header;2;0/statusMessage;1;0", "/httpMessage;1;0"), copy("/body;2;0/bytes;3;0", "/respBytes;3;0"),
                       [d for d in HTTP_CLEAN if d["field"] not in ("/url;1;0", "/method;1;0", "/proxyAlias;1;0", "/keyStoreAlias;1;0", "/keyAlias;1;0", "/trustStore;1;0")]], comment=comment)

def build_headers():
    return [mapstep(setv("/h;2;0/name;1;0", "Accept"), setv("/h;2;0/value;1;0", "application/json")), append_doc("/hdrList;2;1", "/h;2;0"), mapstep(delete("/h;2;0"), comment="the list references the document: start again from a fresh document"),
            branch("/body", ("$null", []), ("$default", [mapstep(setv("/h;2;0/name;1;0", "Content-Type"), copy("/contentType;1;0", "/h;2;0/value;1;0")), append_doc("/hdrList;2;1", "/h;2;0"), mapstep(delete("/h;2;0"))]), comment="Content-Type only with a body"),
            branch("/headers", ("$null", []), ("$default", [
                invoke("pub.document:documentToDocumentList", inp=[copy("/headers;2;0", "/document;2;0"), setv("/name;1;0", "name"), setv("/value;1;0", "value")], out=[copy("/documentList;2;1", "/userHdrs;2;1"), delete("/documentList;2;1", "/document;2;0", "/name;1;0", "/value;1;0")]),
                loop("/userHdrs", None, append_doc("/hdrList;2;1", "/userHdrs;2;0")), mapstep(delete("/userHdrs;2;1", "/headers;2;0"))]), comment="headers provided by the caller"),
            branch("/authHeaderName", ("$null", []), ("$default", [mapstep(copy("/authHeaderName;1;0", "/h;2;0/name;1;0"), copy("/authHeaderValue;1;0", "/h;2;0/value;1;0")), append_doc("/hdrList;2;1", "/h;2;0"), mapstep(delete("/h;2;0"))]), comment="authentication header (dynamic name)"),
            invoke("pub.document:documentListToDocument", inp=[copy("/hdrList;2;1", "/documentList;2;1"), setv("/name;1;0", "name"), setv("/value;1;0", "value")], out=[copy("/document;2;0", "/hdrs;2;0"), delete("/document;2;0", "/documentList;2;1", "/name;1;0", "/value;1;0")]),
            mapstep(delete("/h;2;0", "/hdrList;2;1"))]

API_CALL = service("apiauth.api:call", PKG, sig(field("alias"), field("method"), field("path"), field("body"), field("contentType"), field("headers", "record")),
    sig(field("status"), field("statusMessage"), field("body"), field("json", "record"), field("authType"), field("source"), field("retried"), field("elapsedMs"), field("url")), [
    t0(),
    mapstep(setv("/method;1;0", "get", overwrite=False), setv("/contentType;1;0", "application/json", overwrite=False), setv("/retried;1;0", "false"), setv("/path;1;0", "", overwrite=False)),
    invoke("apiauth.credentials:get", out=[copy("/type;1;0", "/authType;1;0"), delete("/type;1;0", "/expiresIn;1;0")], comment="profile credentials (token managed automatically)"),
    mapstep(setv("/url;1;0", "%baseUrl%%path%", variables=True)),
    branch("/queryName", ("$null", []), ("$default", [
        invoke("pub.string:indexOf", inp=[copy("/url;1;0", "/inString;1;0"), setv("/subString;1;0", "?")], out=[copy("/value;1;0", "/qpos;1;0"), delete("/value;1;0", "/inString;1;0", "/subString;1;0")]),
        branch_expr(("%qpos% < 0", [mapstep(setv("/sep;1;0", "?"))]), ("$default", [mapstep(setv("/sep;1;0", "&"))])),
        url_encode("/queryValue;1;0", "/eq;1;0"),
        mapstep(setv("/url;1;0", "%url%%sep%%queryName%=%eq%", variables=True), delete("/qpos;1;0", "/sep;1;0", "/eq;1;0"))]), comment="API key as query parameter"),
    *build_headers(),
    http_api_call("API call"),
    body_to_string("/respBody;1;0"), mapstep(delete("/respBytes;3;0")),
    branch_expr(("%httpStatus% == \"401\" && %authType% == \"oauth2\"", [
        invoke("apiauth.credentials:get", inp=[setv("/forceRefresh;1;0", "true")], out=[delete("/type;1;0", "/expiresIn;1;0", "/forceRefresh;1;0")], comment="401: token revoked server side, re-authenticating"),
        mapstep(setv("/retried;1;0", "true"), delete("/hdrs;2;0", "/respBody;1;0")),
        log_event("retry-401", "%method% %path%: 401, new token then retry"),
        *build_headers(), http_api_call("retry with the new token"), body_to_string("/respBody;1;0"), mapstep(delete("/respBytes;3;0"))]), comment="a single retry on 401 (OAuth 2 only)"),
    quiet(json_parse("/respBody;1;0", "/json;2;0"), comment="JSON body decoded when possible"),
    *elapsed_ms("/t0;3;0", "/elapsedMs;1;0"),
    mapstep(copy("/httpStatus;1;0", "/status;1;0"), copy("/httpMessage;1;0", "/statusMessage;1;0"), copy("/respBody;1;0", "/body;1;0"),
            delete("/httpStatus;1;0", "/httpMessage;1;0", "/respBody;1;0", "/contentType;1;0", "/method;1;0", "/hdrs;2;0", "/authHeaderName;1;0", "/authHeaderValue;1;0", "/queryName;1;0", "/queryValue;1;0", "/baseUrl;1;0",
                   "/proxyAlias;1;0", "/keyStoreAlias;1;0", "/keyAlias;1;0", "/trustStore;1;0", "/path;1;0")),
], "Calls an API with a profile: authentication (Basic, key, Bearer, OAuth 2 with renewal) is applied automatically; single retry after an OAuth 2 401.")

# ------------------------------------------------------------------ apiauth.admin
REQUIRED = {  # type -> (missing-field expression, message)
    "basic": ("%p/username% == $null || %p/password% == $null", "Basic: username and password are required"),
    "apikey": ("%p/keyValue% == $null", "API key: keyValue is required"),
    "bearer": ("%p/token% == $null", "Static token: token is required"),
}
GRANT_REQUIRED = {
    "client_credentials": ("%p/tokenUrl% == $null || %p/clientId% == $null || %p/clientSecret% == $null", "client_credentials: tokenUrl, clientId and clientSecret are required"),
    "password": ("%p/tokenUrl% == $null || %p/clientId% == $null || %p/username% == $null || %p/password% == $null", "password: tokenUrl, clientId, username and password are required (clientSecret depending on the server)"),
    "refresh_token": ("%p/tokenUrl% == $null || %p/clientId% == $null || %p/refreshToken% == $null", "refresh_token: tokenUrl, clientId and refreshToken are required"),
    "authorization_code": ("%p/tokenUrl% == $null || %p/authUrl% == $null || %p/clientId% == $null || %p/redirectUri% == $null", "authorization_code: tokenUrl, authUrl, clientId and redirectUri are required"),
    "jwt_bearer": ("%p/tokenUrl% == $null || %p/clientId% == $null || %p/keyStoreAlias% == $null || %p/keyAlias% == $null", "jwt_bearer: tokenUrl, clientId (issuer), keyStoreAlias and keyAlias are required"),
}
SECRET_FIELDS = ("password", "clientSecret", "keyValue", "token", "refreshToken")

def strip_empty():
    """Empty strings sent by a form count as absent."""
    nodes = []
    for f in ("baseUrl", "tokenUrl", "authUrl", "clientId", "clientSecret", "clientAuth", "scope", "audience", "resource", "username", "password", "refreshToken", "redirectUri", "keyName", "keyValue", "keyIn", "keyPrefix",
              "token", "headerName", "prefix", "keyStoreAlias", "keyAlias", "jwtAlgorithm", "jwtIssuer", "jwtSubject", "jwtAudience", "proxyAlias", "trustStore", "testPath", "authExtra", "preset", "grant", "pkce"):
        nodes.append(branch(f"/p/{f}", ("", [mapstep(delete(f"/p;2;0/{f};1;0"))])))
    return nodes

SAVE_PROFILE = service("apiauth.admin:saveProfile", PKG, sig(field("profileJson"), field("keepToken")), sig(field("ok"), field("message"), field("alias"), field("type")), [
    branch("/profileJson", ("$null", [exit_("$flow", "FAILURE", "profileJson is required")])),
    json_parse("/profileJson;1;0", "/p;2;0"),
    *strip_empty(),
    branch_expr(("%p/alias% == $null || %p/alias% == \"\"", [exit_("$flow", "FAILURE", "The profile name (alias) is required")]), ("%p/type% == $null", [exit_("$flow", "FAILURE", "The profile type is required (none, basic, apikey, bearer, oauth2)")])),
    branch("/p/type",
        ("none", []),
        *[(t, [branch_expr((expr, [exit_("$flow", "FAILURE", msg)]))]) for t, (expr, msg) in REQUIRED.items()],
        ("oauth2", [branch("/p/grant", *[(g, [branch_expr((expr, [exit_("$flow", "FAILURE", msg)]))]) for g, (expr, msg) in GRANT_REQUIRED.items()],
                           ("$default", [exit_("$flow", "FAILURE", "OAuth 2 grant required: client_credentials, password, refresh_token, authorization_code or jwt_bearer")]))]),
        ("$default", [exit_("$flow", "FAILURE", "Unknown profile type: %p/type%")]), comment="validation by type / grant"),
    mapstep(copy("/p;2;0/alias;1;0", "/alias;1;0"), copy("/p;2;0/type;1;0", "/type;1;0")),
    store_get("apiauth.profile.%alias%", "/oldJson;1;0"),
    branch("/oldJson", ("$null", []), ("$default", [json_parse("/oldJson;1;0", "/old;2;0"),
        *[branch(f"/p/{f}", ("$null", [mapstep(copy(f"/old;2;0/{f};1;0", f"/p;2;0/{f};1;0"))])) for f in SECRET_FIELDS],
        mapstep(delete("/old;2;0"))]), comment="edit: a missing secret keeps the value already in the store"),
    now_str("/savedAt;1;0"), mapstep(copy("/savedAt;1;0", "/p;2;0/savedAt;1;0")),
    json_string("/p;2;0", "/cfgJson;1;0"),
    store_set("apiauth.profile.%alias%", "/cfgJson;1;0"),
    branch("/keepToken", ("true", []), ("$default", [store_remove("apiauth.token.%alias%")])),
    log_event("config", "profile saved (type %type%)"),
    mapstep(setv("/ok;1;0", "true"), setv("/message;1;0", "Profile saved; secrets are encrypted in the Integration Server store"), delete("/p;2;0", "/cfgJson;1;0", "/profileJson;1;0", "/savedAt;1;0", "/keepToken;1;0", "/oldJson;1;0")),
], "Saves (or replaces) an access profile from its JSON; validation by type and grant; secrets encrypted in the store.")

DELETE_PROFILE = service("apiauth.admin:deleteProfile", PKG, sig(field("alias")), sig(field("ok")), [
    store_remove("apiauth.profile.%alias%"), store_remove("apiauth.token.%alias%"), log_event("config", "profile deleted"), mapstep(setv("/ok;1;0", "true")),
], "Deletes a profile and its token.")

DISCONNECT = service("apiauth.admin:disconnect", PKG, sig(field("alias")), sig(field("ok")), [
    store_remove("apiauth.token.%alias%"), log_event("config", "token forgotten (disconnect)"), mapstep(setv("/ok;1;0", "true")),
], "Forgets the token (and refresh token) of a profile without touching its configuration.")

PUBLIC_FIELDS = ("alias", "type", "grant", "baseUrl", "tokenUrl", "authUrl", "clientId", "clientAuth", "scope", "audience", "resource", "username", "redirectUri", "pkce", "keyName", "keyIn", "keyPrefix", "headerName", "prefix",
                 "keyStoreAlias", "keyAlias", "jwtAlgorithm", "jwtIssuer", "jwtSubject", "jwtAudience", "proxyAlias", "trustStore", "testPath", "authExtra", "preset", "savedAt")

LIST_PROFILES = service("apiauth.admin:listProfiles", PKG, sig(), sig(field("serverTime"), field("profiles", "record", 1), field("events", "record", 1)), [
    now_str("/serverTime;1;0"), now_str("/serverTimeNum;1;0", DTN),
    invoke("apiauth.store:list", out=[copy("/keys;2;1", "/allKeys;2;1"), delete("/keys;2;1")]),
    loop("/allKeys", None,
         invoke("pub.string:indexOf", inp=[copy("/allKeys;2;0/name;1;0", "/inString;1;0"), setv("/subString;1;0", "apiauth.profile.")], out=[copy("/value;1;0", "/pos;1;0"), delete("/value;1;0", "/inString;1;0", "/subString;1;0")]),
         branch("/pos", ("0", [
             invoke("apiauth.store:get", inp=[copy("/allKeys;2;0/name;1;0", "/key;1;0")], out=[copy("/value;1;0", "/cfgJson;1;0"), delete("/key;1;0", "/value;1;0")]),
             json_parse("/cfgJson;1;0", "/cfg;2;0"),
             mapstep(*[copy(f"/cfg;2;0/{f};1;0", f"/entry;2;0/{f};1;0") for f in PUBLIC_FIELDS], copy("/cfg;2;0/extraParams;2;0", "/entry;2;0/extraParams;2;0"), copy("/cfg;2;0/jwtClaims;2;0", "/entry;2;0/jwtClaims;2;0"), comment="never the secrets"),
             *[branch(f"/cfg/{f}", ("$null", []), ("$default", [mapstep(setv(f"/entry;2;0/has_{f};1;0", "true"))])) for f in SECRET_FIELDS],
             invoke("apiauth.store:get", inp=[setv("/key;1;0", "apiauth.token.%cfg/alias%", variables=True)], out=[copy("/value;1;0", "/tokJson;1;0"), delete("/key;1;0", "/value;1;0")]),
             branch("/tokJson", ("$null", []), ("$default", [
                 json_parse("/tokJson;1;0", "/tok;2;0"), mapstep(setv("/entry;2;0/tokenExpiresIn;1;0", "0")),
                 branch_expr(("%tok/expiresAtNum% > %serverTimeNum%", [secs_remaining("/serverTime;1;0", "/tok;2;0/expiresAt;1;0", "/entry;2;0/tokenExpiresIn;1;0")])),
                 mapstep(copy("/tok;2;0/expiresAt;1;0", "/entry;2;0/tokenExpiresAt;1;0"), copy("/tok;2;0/obtainedAt;1;0", "/entry;2;0/tokenObtainedAt;1;0"), copy("/tok;2;0/source;1;0", "/entry;2;0/tokenSource;1;0"), copy("/tok;2;0/expiresIn;1;0", "/entry;2;0/tokenLifetime;1;0")),
                 branch("/tok/refresh_token", ("$null", []), ("$default", [mapstep(setv("/entry;2;0/hasRefreshToken;1;0", "true"))])), mapstep(delete("/tok;2;0"))])),
             append_doc("/profiles;2;1", "/entry;2;0"), mapstep(delete("/entry;2;0", "/cfg;2;0", "/cfgJson;1;0", "/tokJson;1;0"))])),
         mapstep(delete("/pos;1;0")), comment="one entry per apiauth.profile.* key"),
    store_get("apiauth.events", "/evJson;1;0"),
    branch("/evJson", ("$null", []), ("$default", [json_parse("/evJson;1;0", "/journal;2;0"), mapstep(copy("/journal;2;0/events;2;1", "/events;2;1"), delete("/journal;2;0"))])),
    mapstep(delete("/allKeys;2;1", "/evJson;1;0", "/serverTimeNum;1;0")),
], "Lists the profiles (without secrets, with presence flags), their token state and the journal.")

TEST_PROFILE = service("apiauth.admin:testProfile", PKG, sig(field("alias")), sig(field("ok"), field("message"), field("source"), field("expiresIn"), field("status"), field("elapsedMs")), [
    t0(),
    *try_catch([
        invoke("apiauth.credentials:get", inp=[setv("/forceRefresh;1;0", "true")], out=[delete("/forceRefresh;1;0")], comment="credentials (forced token for OAuth 2)"),
        branch("/type", ("oauth2", [mapstep(setv("/message;1;0", "Token obtained (%source%), valid for %expiresIn% s", variables=True))]),
                        ("none", [mapstep(setv("/message;1;0", "No authentication"))]),
                        ("$default", [mapstep(setv("/message;1;0", "Credentials ready (%type%)", variables=True))])),
        *load_profile(),
        branch("/cfg/testPath", ("$null", []), ("$default", [
            invoke("apiauth.api:call", inp=[copy("/cfg;2;0/testPath;1;0", "/path;1;0"), setv("/method;1;0", "get")],
                   out=[delete("/statusMessage;1;0", "/body;1;0", "/json;2;0", "/authType;1;0", "/retried;1;0", "/elapsedMs;1;0", "/url;1;0", "/path;1;0", "/method;1;0")], comment="verification call (GET testPath)"),
            branch_expr(("%status% >= 200 && %status% < 300", [mapstep(setv("/message;1;0", "%message%; GET %cfg/testPath%: HTTP %status%", variables=True))]),
                        ("$default", [exit_("$parent", "FAILURE", "%message%; but GET %cfg/testPath% answers HTTP %status%")]))]), comment="call test when the profile defines testPath"),
        mapstep(setv("/ok;1;0", "true"), delete("/authHeaderName;1;0", "/authHeaderValue;1;0", "/queryName;1;0", "/queryValue;1;0", "/baseUrl;1;0", "/type;1;0", "/cfg;2;0", "/proxyAlias;1;0", "/keyStoreAlias;1;0", "/keyAlias;1;0", "/trustStore;1;0")),
    ], [
        invoke("pub.flow:getLastFailureCaught", out=[copy("/failureMessage;1;0", "/message;1;0"), delete("/failureMessage;1;0", "/failureName;1;0", "/failure;3;0")]),
        mapstep(setv("/ok;1;0", "false"), delete("/authHeaderName;1;0", "/authHeaderValue;1;0", "/queryName;1;0", "/queryValue;1;0", "/baseUrl;1;0", "/type;1;0", "/cfg;2;0", "/proxyAlias;1;0", "/keyStoreAlias;1;0", "/keyAlias;1;0", "/trustStore;1;0", "/source;1;0", "/tokenError;1;0")),
        log_event("error", "%message%"),
    ]),
    *elapsed_ms("/t0;3;0", "/elapsedMs;1;0"),
], "Tests a profile: obtains the credentials (forced token for OAuth 2) then, when testPath is defined, a verification GET.")

SERVICES = [STORE_SET, STORE_GET, STORE_REMOVE, STORE_LIST, LOG_EVENT, TOKEN_REQUEST, STORE_TOKEN, TOKEN, AUTHORIZE_URL, CALLBACK, CREDENTIALS, API_CALL, SAVE_PROFILE, DELETE_PROFILE, DISCONNECT, LIST_PROFILES, TEST_PROFILE]


def deploy_all(m):
    ensure_package(m, PKG, ["apiauth", "apiauth.store", "apiauth.log", "apiauth.oauth", "apiauth.credentials", "apiauth.api", "apiauth.admin"])
    return deploy(m, PKG, SERVICES)


# ------------------------------------------------------------------ tests against mock/auth_mock.py
MOCK = "http://localhost:8086"
IS_URL = "http://localhost:5555"
CLIENT_ID, CLIENT_SECRET = "demo-client-id", "demo-client-secret"

def inv(m, svc, inputs=None, maxlen=300):
    args = {"service_path": svc}
    if inputs is not None: args["inputs"] = json.dumps(inputs)
    try:
        raw = m.call("service_invoke", args)
        try: d = json.loads(raw)
        except json.JSONDecodeError: raise RuntimeError(raw[:600])
        print(f"OK  {svc}: {json.dumps(d, ensure_ascii=False)[:maxlen]}"); return d
    except Exception as e:
        print(f"KO  {svc}: {str(e)[:600]}"); return None

def mock(path, data=None):
    req = urllib.request.Request(MOCK + path, data=(urllib.parse.urlencode(data).encode() if data is not None else None), method="POST" if data is not None else "GET")
    return json.loads(urllib.request.urlopen(req, timeout=5).read())

def save(m, **p):
    return inv(m, "apiauth.admin:saveProfile", {"profileJson": json.dumps(p)}, 200)

def call(m, alias, path, expect="200", **kw):
    r = inv(m, "apiauth.api:call", {"alias": alias, "path": path, **kw}, 220)
    assert r and r.get("status") == expect, f"{alias}: expected HTTP {expect}"
    return r

def tests(m):
    try: mock("/admin/ttl")
    except Exception: sys.exit("simulator not running: python3 mock/auth_mock.py 8086 &")
    mock("/admin/ttl", {"seconds": 90})
    oauth = dict(type="oauth2", baseUrl=MOCK, tokenUrl=MOCK + "/oauth/token", clientId=CLIENT_ID, clientSecret=CLIENT_SECRET, testPath="/api/bearer/customers/T1")
    print("--- profiles: basic, apikey (header and query), static bearer, none ---")
    save(m, alias="t-basic", type="basic", baseUrl=MOCK, username="basic-user", password="basic-pass", testPath="/api/basic/customers/T1")
    save(m, alias="t-apikey", type="apikey", baseUrl=MOCK, keyName="X-API-Key", keyValue="key-demo-123", keyIn="header")
    save(m, alias="t-apikey-q", type="apikey", baseUrl=MOCK, keyName="api_key", keyValue="key-demo-123", keyIn="query")
    save(m, alias="t-bearer", type="bearer", baseUrl=MOCK, token="static-demo-token")
    save(m, alias="t-none", type="none", baseUrl=MOCK)
    call(m, "t-basic", "/api/basic/customers/C1"); call(m, "t-apikey", "/api/apikey/customers/C2"); call(m, "t-apikey-q", "/api/apikey/customers/C3?x=1")
    call(m, "t-bearer", "/api/static/customers/C4"); call(m, "t-none", "/api/open/customers/C5")
    r = call(m, "t-basic", "/api/apikey/customers/C6", expect="401"); assert r.get("retried") == "false", "no retry outside OAuth 2"
    print("--- OAuth 2 client_credentials (client in the body, then as Basic) ---")
    save(m, alias="t-cc", grant="client_credentials", scope="read", **oauth)
    r = call(m, "t-cc", "/api/bearer/customers/C7"); assert r.get("source") == "client_credentials"
    r = call(m, "t-cc", "/api/bearer/customers/C8"); assert r.get("source") == "cache"
    save(m, alias="t-cc-basic", grant="client_credentials", clientAuth="basic", **oauth)
    r = inv(m, "apiauth.admin:testProfile", {"alias": "t-cc-basic"}); assert r and r.get("ok") == "true", "Basic client failed"
    print("--- OAuth 2 password (service account) + refresh + expiry + revocation ---")
    save(m, alias="t-pwd", grant="password", username="svc-user", password="svc-pass", **oauth)
    r = call(m, "t-pwd", "/api/bearer/customers/C9"); assert r.get("source") == "password"
    mock("/admin/ttl", {"seconds": 20}); inv(m, "apiauth.admin:testProfile", {"alias": "t-pwd"}); time.sleep(17)
    r = call(m, "t-pwd", "/api/bearer/customers/C10"); assert r.get("source") == "refresh" and r.get("retried") == "false", "silent renewal failed"
    mock("/admin/ttl", {"seconds": 90}); inv(m, "apiauth.admin:testProfile", {"alias": "t-pwd"}); mock("/admin/revoke", {})
    r = call(m, "t-pwd", "/api/bearer/customers/C11"); assert r.get("retried") == "true", "retry after 401 failed"
    print("--- OAuth 2 refresh_token provided once (rotation) ---")
    seed = mock("/oauth/token", {"grant_type": "password", "username": "svc-user", "password": "svc-pass", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})["refresh_token"]
    save(m, alias="t-rt", grant="refresh_token", refreshToken=seed, **oauth)
    r = call(m, "t-rt", "/api/bearer/customers/C12"); assert r.get("source") == "refresh"
    mock("/admin/revoke", {}); r = call(m, "t-rt", "/api/bearer/customers/C13"); assert r.get("retried") == "true" and r.get("source") == "refresh", "refresh token rotation failed"
    print("--- OAuth 2 jwt_bearer (assertion signed by the IS keystore key) ---")
    save(m, alias="t-jwt", grant="jwt_bearer", keyStoreAlias="DEFAULT_IS_KEYSTORE", keyAlias="ssos", jwtSubject="svc-user", jwtClaims={"scope": "read write"}, **oauth)
    r = call(m, "t-jwt", "/api/bearer/customers/C14"); assert r.get("source") == "jwt_bearer"
    print("--- OAuth 2 authorization_code + PKCE: URL, simulated consent, callback ---")
    save(m, alias="t-ac", grant="authorization_code", authUrl=MOCK + "/oauth/authorize", redirectUri=IS_URL + "/invoke/apiauth.oauth/callback", scope="profile", **oauth)
    r = inv(m, "apiauth.api:call", {"alias": "t-ac", "path": "/api/bearer/customers/C15"}); assert r is None, "a profile that is not connected must fail clearly"
    u = inv(m, "apiauth.oauth:authorizeUrl", {"alias": "t-ac"}, 400); assert u and "code_challenge=" in u["url"]
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(u["url"]).query))
    req = urllib.request.Request(MOCK + "/oauth/authorize", data=urllib.parse.urlencode(dict(q, approve="1")).encode(), method="POST")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    try: urllib.request.build_opener(NoRedirect).open(req, timeout=5); loc = None
    except urllib.error.HTTPError as e: loc = e.headers.get("Location")
    assert loc and "code=" in loc, "no redirect with a code"
    cb = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
    import base64
    rq = urllib.request.Request(IS_URL + "/invoke/apiauth.oauth/callback?" + urllib.parse.urlencode(cb), headers={"Authorization": "Basic " + base64.b64encode(b"Administrator:manage").decode()})
    html = urllib.request.urlopen(rq, timeout=30).read().decode(); assert "Connected" in html, html[:300]
    print("OK  callback: " + html[html.find("<h2>"):html.find("</h2>") + 5])
    r = call(m, "t-ac", "/api/bearer/customers/C15"); assert r.get("source") == "cache"
    mock("/admin/revoke", {}); r = call(m, "t-ac", "/api/bearer/customers/C16"); assert r.get("retried") == "true" and r.get("source") == "refresh"
    print("--- readable errors ---")
    save(m, alias="t-bad", grant="password", username="svc-user", password="wrong", **oauth)
    r = inv(m, "apiauth.admin:testProfile", {"alias": "t-bad"}); assert r and r.get("ok") == "false" and "HTTP 401" in r["message"]
    r = inv(m, "apiauth.admin:saveProfile", {"profileJson": json.dumps({"alias": "t-inc", "type": "oauth2", "grant": "client_credentials", "tokenUrl": ""})}); assert r is None, "incomplete profile accepted"
    save(m, alias="t-basic", type="basic", baseUrl=MOCK, username="basic-user", testPath="/api/basic/customers/T2")
    r = inv(m, "apiauth.admin:testProfile", {"alias": "t-basic"}); assert r and r.get("ok") == "true", "secret not kept on edit"
    r = inv(m, "apiauth.admin:listProfiles", maxlen=400); assert r and not any(k in json.dumps(r) for k in ("basic-pass", "key-demo-123", "static-demo-token", CLIENT_SECRET)), "secret exposed in the listing"
    for a in ("t-basic", "t-apikey", "t-apikey-q", "t-bearer", "t-none", "t-cc", "t-cc-basic", "t-pwd", "t-rt", "t-jwt", "t-ac", "t-bad"):
        inv(m, "apiauth.admin:deleteProfile", {"alias": a}, 60)
    print("TESTS OK")


if __name__ == "__main__":
    what = sys.argv[1:] or ["deploy", "test"]
    m = Mcp()
    try:
        if "deploy" in what and not deploy_all(m): sys.exit(1)
        if "test" in what: tests(m)
    finally:
        m.close()
