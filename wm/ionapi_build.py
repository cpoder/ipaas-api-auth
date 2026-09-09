#!/usr/bin/env python3
"""IonApiClient package (ION API client / OAuth 2 with a service account, without manual token handling)
and IonApiMock package (fake token server + fake M3 for the demo). Built with putNode through the MCP server.

Usage: ionapi_build.py [deploy] [test]
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcpcli import Mcp
from putnode_builder import *

PKG, MOCK = "IonApiClient", "IonApiMock"
DT = "yyyy-MM-dd HH:mm:ss"
DTN = "yyyyMMddHHmmss"   # same instant as a comparable number (calculateDateDifference returns an absolute value)
S = lambda n: f"/{n};1;0"          # string
O = lambda n: f"/{n};3;0"          # object
R = lambda n: f"/{n};2;0"          # record

# ------------------------------------------------------------------ building blocks
def now_str(target, pattern=DT):
    return invoke("pub.date:getCurrentDateString", inp=[setv("/pattern;1;0", pattern)], out=[copy("/value;1;0", target), delete("/value;1;0", "/pattern;1;0")])

def json_parse(src, target):
    return invoke("pub.json:jsonStringToDocument", inp=[copy(src, "/jsonString;1;0")], out=[copy("/document;2;0", target), delete("/document;2;0", "/jsonString;1;0")])

def json_string(doc, target):
    return invoke("pub.json:documentToJSONString", inp=[copy(doc, "/document;2;0")], out=[copy("/jsonString;1;0", target), delete("/jsonString;1;0", "/document;2;0")])

def store_get(key_expr, target):
    """ionapi.store:get -> target (absent when the key does not exist)."""
    return invoke("ionapi.store:get", inp=[setv("/key;1;0", key_expr, variables=True)], out=[copy("/value;1;0", target), delete("/key;1;0", "/value;1;0")])

def store_set(key_expr, value_path):
    return invoke("ionapi.store:set", inp=[setv("/key;1;0", key_expr, variables=True), copy(value_path, "/value;1;0")], out=[delete("/key;1;0", "/value;1;0")])

def store_remove(key_expr):
    return invoke("ionapi.store:remove", inp=[setv("/key;1;0", key_expr, variables=True)], out=[delete("/key;1;0")])

def elapsed_ms(t0, target):
    return [invoke("pub.date:elapsedNanoTime", inp=[copy(t0, "/nanoTime;3;0")], out=[copy("/elapsedNanoTime;3;0", "/elNs;3;0"), delete("/elapsedNanoTime;3;0", "/elapsedNanoTimeStr;1;0", "/nanoTime;3;0")]),
            invoke("pub.string:objectToString", inp=[copy("/elNs;3;0", "/object;3;0")], out=[copy("/string;1;0", "/elNsStr;1;0"), delete("/string;1;0", "/object;3;0", "/elNs;3;0")]),
            invoke("pub.math:divideFloats", inp=[copy("/elNsStr;1;0", "/num1;1;0"), setv("/num2;1;0", "1000000"), setv("/precision;1;0", "0")], out=[copy("/value;1;0", "/msF;1;0"), delete("/value;1;0", "/num1;1;0", "/num2;1;0", "/precision;1;0", "/elNsStr;1;0")]),
            invoke("pub.math:roundNumber", inp=[copy("/msF;1;0", "/num;1;0"), setv("/numberOfDigits;1;0", "0")], out=[copy("/roundedNumber;1;0", target), delete("/roundedNumber;1;0", "/num;1;0", "/numberOfDigits;1;0", "/msF;1;0", t0)])]

HTTP_CLEAN = delete("/url;1;0", "/method;1;0", "/data;2;0", "/loadAs;1;0", "/throwExceptionOnHttp401;1;0", "/timeout;1;0", "/header;2;0", "/lines;2;0", "/body;2;0", "/status;1;0", "/statusMessage;1;0", "/encodedURL;1;0", "/headers;2;0")

def body_to_string(target):
    """body/bytes -> string (absent when there is no body)."""
    return branch("/respBytes", ("$null", []), ("$default", [invoke("pub.string:bytesToString", inp=[copy("/respBytes;3;0", "/bytes;3;0")], out=[copy("/string;1;0", target), delete("/string;1;0", "/bytes;3;0")])]))

def token_request(args, comment):
    """POST form-urlencoded to tokenUrl -> httpStatus, respJson."""
    inp = [copy("/tokenUrl;1;0", "/url;1;0"), setv("/method;1;0", "post"), setv("/loadAs;1;0", "bytes"), setv("/throwExceptionOnHttp401;1;0", "false"), setv("/timeout;1;0", "20000")]
    for name, src, const in args:
        inp.append(setv(f"/data;2;0/args;2;0/{name};1;0", src) if const else copy(src, f"/data;2;0/args;2;0/{name};1;0"))
    return [invoke("pub.client:http", inp=inp, out=[copy("/header;2;0/status;1;0", "/httpStatus;1;0"), copy("/body;2;0/bytes;3;0", "/respBytes;3;0"), HTTP_CLEAN], comment=comment),
            body_to_string("/respJson;1;0"), mapstep(delete("/respBytes;3;0"))]

def take_token(source):
    return [json_parse("/respJson;1;0", "/resp;2;0"),
            mapstep(copy("/resp;2;0/access_token;1;0", "/newToken;1;0"), copy("/resp;2;0/refresh_token;1;0", "/newRefresh;1;0"), copy("/resp;2;0/expires_in;3;0", "/expObj;3;0"),
                    setv("/tokenSource;1;0", source), setv("/expiresInRaw;1;0", "3600"), delete("/resp;2;0")),
            branch("/expObj", ("$null", []), ("$default", [invoke("pub.string:objectToString", inp=[copy("/expObj;3;0", "/object;3;0")], out=[copy("/string;1;0", "/expiresInRaw;1;0"), delete("/string;1;0", "/object;3;0")])]),
                   comment="expires_in arrives as a JSON number (Long): converted to a string, 3600 s by default"),
            mapstep(delete("/expObj;3;0"))]

def reject(code, body):
    return [invoke("pub.flow:setResponseCode", inp=[setv("/responseCode;1;0", code)], out=[delete("/responseCode;1;0")]),
            invoke("pub.flow:setResponse", inp=[setv("/responseString;1;0", body), setv("/contentType;1;0", "application/json")], out=[delete("/responseString;1;0", "/contentType;1;0")]),
            exit_("$flow", "SUCCESS")]

def respond_json(src):
    return invoke("pub.flow:setResponse", inp=[copy(src, "/responseString;1;0"), setv("/contentType;1;0", "application/json")], out=[delete("/responseString;1;0", "/contentType;1;0")])

# ------------------------------------------------------------------ ionapi.store: outbound password store (encrypted)
STORE_SET = service("ionapi.store:set", PKG, sig(field("key"), field("value")), sig(), [
    invoke("pub.security.util:createSecureString", inp=[copy("/value;1;0", "/string;1;0")], out=[copy("/secureString;3;0", "/ss;3;0"), delete("/secureString;3;0", "/string;1;0")]),
    quiet(invoke("pub.security.outboundPasswords:removePassword", inp=[setv("/isInternal;1;0", "false")], out=[delete("/result;1;0", "/message;1;0", "/isInternal;1;0")]), comment="replacement: prior removal ignored when absent"),
    invoke("pub.security.outboundPasswords:setPassword", inp=[copy("/ss;3;0", "/password;3;0"), setv("/isInternal;1;0", "false")],
           out=[delete("/password;3;0", "/isInternal;1;0", "/result;1;0", "/message;1;0", "/ss;3;0")]),
], "Writes a value (string) into the IS outbound password store, encrypted at rest (key -> value).")

STORE_GET = service("ionapi.store:get", PKG, sig(field("key")), sig(field("value")), [
    invoke("pub.security.outboundPasswords:getPassword", inp=[setv("/isInternal;1;0", "false")],
           out=[copy("/password;3;0", "/ss;3;0"), delete("/password;3;0", "/isInternal;1;0", "/result;1;0", "/message;1;0")]),
    branch("/ss", ("$null", []), ("$default", [
        invoke("pub.security.util:convertSecureString", inp=[copy("/ss;3;0", "/secureString;3;0"), setv("/returnAs;1;0", "string")],
               out=[copy("/string;1;0", "/value;1;0"), delete("/string;1;0", "/secureString;3;0", "/returnAs;1;0")])])),
    mapstep(delete("/ss;3;0")),
], "Reads a value from the store (value absent when the key does not exist).")

STORE_REMOVE = service("ionapi.store:remove", PKG, sig(field("key")), sig(), [
    quiet(invoke("pub.security.outboundPasswords:removePassword", inp=[setv("/isInternal;1;0", "false")], out=[delete("/isInternal;1;0", "/result;1;0", "/message;1;0")])),
], "Removes a key from the store (silent when absent).")

STORE_LIST = service("ionapi.store:list", PKG, sig(), sig(field("keys", "record", 1)), [
    invoke("pub.security.outboundPasswords:listKeys", inp=[setv("/isInternal;1;0", "false")], out=[delete("/isInternal;1;0", "/name;1;0")]),
], "Lists the store keys.")

# ------------------------------------------------------------------ ionapi.token
LOG_EVENT = service("ionapi.token:logEvent", PKG, sig(field("alias"), field("event"), field("detail")), sig(), [
    now_str("/time;1;0"),
    store_get("ionapi.events", "/evJson;1;0"),
    branch("/evJson", ("$null", []), ("$default", [json_parse("/evJson;1;0", "/journal;2;0")])),
    mapstep(copy("/time;1;0", "/ev;2;0/time;1;0"), copy("/alias;1;0", "/ev;2;0/alias;1;0"), copy("/event;1;0", "/ev;2;0/event;1;0"), copy("/detail;1;0", "/ev;2;0/detail;1;0")),
    invoke("pub.list:appendToDocumentList", inp=[copy("/journal;2;0/events;2;1", "/toList;2;1"), copy("/ev;2;0", "/fromItem;2;0")],
           out=[copy("/toList;2;1", "/journal;2;0/events;2;1"), delete("/toList;2;1", "/fromItem;2;0")]),
    json_string("/journal;2;0", "/newJson;1;0"),
    invoke("pub.string:length", inp=[copy("/newJson;1;0", "/inString;1;0")], out=[copy("/value;1;0", "/len;1;0"), delete("/value;1;0", "/inString;1;0")]),
    branch_expr(("%len% > 20000", [
        mapstep(delete("/journal;2;0", "/newJson;1;0")),
        invoke("pub.list:appendToDocumentList", inp=[copy("/ev;2;0", "/fromItem;2;0")], out=[copy("/toList;2;1", "/journal;2;0/events;2;1"), delete("/toList;2;1", "/fromItem;2;0")]),
        json_string("/journal;2;0", "/newJson;1;0")]), comment="capped journal: restarts from the last event beyond 20 KB"),
    store_set("ionapi.events", "/newJson;1;0"),
    mapstep(delete("/time;1;0", "/evJson;1;0", "/journal;2;0", "/ev;2;0", "/newJson;1;0", "/len;1;0", "/event;1;0", "/detail;1;0")),
], "Token event journal (obtained, renewed, refused) kept in the store.")

TOKEN_GET = service("ionapi.token:get", PKG, sig(field("alias"), field("forceRefresh")), sig(field("accessToken"), field("tokenSource"), field("expiresAt"), field("expiresIn"), field("apiBaseUrl")), [
    *try_catch([
    store_get("ionapi.alias.%alias%", "/cfgJson;1;0"),
    branch("/cfgJson", ("$null", [exit_("$parent", "FAILURE", "Unknown ION API access: %alias%")])),
    json_parse("/cfgJson;1;0", "/cfg;2;0"),
    mapstep(copy("/cfg;2;0/apiBaseUrl;1;0", "/apiBaseUrl;1;0"), copy("/cfg;2;0/tokenUrl;1;0", "/tokenUrl;1;0"), setv("/valid;1;0", "false"), setv("/forceRefresh;1;0", "false", overwrite=False), delete("/cfgJson;1;0")),
    now_str("/now;1;0"), now_str("/nowNum;1;0", DTN),
    store_get("ionapi.token.%alias%", "/tokJson;1;0"),
    branch("/tokJson", ("$null", []), ("$default", [
        json_parse("/tokJson;1;0", "/tok;2;0"),
        branch_expr(("%forceRefresh% != \"true\" && %tok/expiresAtNum% > %nowNum%", [
            mapstep(setv("/valid;1;0", "true")),
            invoke("pub.date:calculateDateDifference", inp=[copy("/now;1;0", "/startDate;1;0"), copy("/tok;2;0/expiresAt;1;0", "/endDate;1;0"), setv("/startDatePattern;1;0", DT), setv("/endDatePattern;1;0", DT)],
                   out=[copy("/dateDifferenceSeconds;1;0", "/remaining;1;0"), delete("/dateDifferenceSeconds;1;0", "/dateDifferenceMinutes;1;0", "/dateDifferenceHours;1;0", "/dateDifferenceDays;1;0", "/startDate;1;0", "/endDate;1;0", "/startDatePattern;1;0", "/endDatePattern;1;0")],
                   comment="remaining seconds")]), comment="token still valid (numeric comparison of instants)?"),
    ]), comment="token already known for this access?"),
    branch("/valid",
           ("true", [mapstep(copy("/tok;2;0/access_token;1;0", "/accessToken;1;0"), copy("/tok;2;0/expiresAt;1;0", "/expiresAt;1;0"), copy("/remaining;1;0", "/expiresIn;1;0"), setv("/tokenSource;1;0", "cache"), comment="cached token still valid")]),
           ("$default", [
               branch_expr(("%tok/refresh_token% != $null && %forceRefresh% != \"true\"", [
                   quiet(token_request([("grant_type", "refresh_token", True), ("refresh_token", "/tok;2;0/refresh_token;1;0", False), ("client_id", "/cfg;2;0/clientId;1;0", False), ("client_secret", "/cfg;2;0/clientSecret;1;0", False)], "refresh_token grant"),
                         branch("/httpStatus", ("200", take_token("refresh"))),
                         mapstep(delete("/respJson;1;0", "/httpStatus;1;0")), comment="renewal with the refresh token, failure ignored (falls back to the password grant)")])),
               branch("/newToken", ("$null", [
                   token_request([("grant_type", "password", True), ("username", "/cfg;2;0/saak;1;0", False), ("password", "/cfg;2;0/sask;1;0", False), ("client_id", "/cfg;2;0/clientId;1;0", False), ("client_secret", "/cfg;2;0/clientSecret;1;0", False), ("scope", "/cfg;2;0/scope;1;0", False)],
                                 "password grant: service account (saak / sask) + client id / secret"),
                   branch("/httpStatus", ("200", take_token("password")), ("$default", [exit_("$parent", "FAILURE", "Authentication refused by the token server (HTTP %httpStatus%): %respJson%")])),
                   mapstep(delete("/respJson;1;0", "/httpStatus;1;0"))]), comment="no token: authentication with the service account"),
               branch("/newToken", ("$null", [exit_("$parent", "FAILURE", "The token server did not return an access_token")])),
               branch_expr(("%expiresInRaw% < 60", [mapstep(setv("/margin;1;0", "5"))]), ("$default", [mapstep(setv("/margin;1;0", "30"))]), comment="safety margin: 30 s, or 5 s for short-lived tokens"),
               invoke("pub.math:subtractInts", inp=[copy("/expiresInRaw;1;0", "/num1;1;0"), copy("/margin;1;0", "/num2;1;0")], out=[copy("/value;1;0", "/ttl;1;0"), delete("/value;1;0", "/num1;1;0", "/num2;1;0", "/margin;1;0")]),
               invoke("pub.date:incrementDate", inp=[copy("/now;1;0", "/startDate;1;0"), setv("/startDatePattern;1;0", DT), setv("/endDatePattern;1;0", DT), copy("/ttl;1;0", "/addSeconds;1;0")],
                      out=[copy("/endDate;1;0", "/expiresAt;1;0"), delete("/endDate;1;0", "/startDate;1;0", "/startDatePattern;1;0", "/endDatePattern;1;0", "/addSeconds;1;0")]),
               invoke("pub.date:incrementDate", inp=[copy("/now;1;0", "/startDate;1;0"), setv("/startDatePattern;1;0", DT), setv("/endDatePattern;1;0", DTN), copy("/ttl;1;0", "/addSeconds;1;0")],
                      out=[copy("/endDate;1;0", "/expiresAtNum;1;0"), delete("/endDate;1;0", "/startDate;1;0", "/startDatePattern;1;0", "/endDatePattern;1;0", "/addSeconds;1;0")]),
               mapstep(copy("/newToken;1;0", "/tokState;2;0/access_token;1;0"), copy("/newRefresh;1;0", "/tokState;2;0/refresh_token;1;0"), copy("/expiresAt;1;0", "/tokState;2;0/expiresAt;1;0"), copy("/expiresAtNum;1;0", "/tokState;2;0/expiresAtNum;1;0"),
                       copy("/now;1;0", "/tokState;2;0/obtainedAt;1;0"), copy("/tokenSource;1;0", "/tokState;2;0/source;1;0"), copy("/expiresInRaw;1;0", "/tokState;2;0/expiresIn;1;0")),
               json_string("/tokState;2;0", "/tokStateJson;1;0"),
               store_set("ionapi.token.%alias%", "/tokStateJson;1;0"),
               invoke("ionapi.token:logEvent", inp=[copy("/tokenSource;1;0", "/event;1;0"), setv("/detail;1;0", "token obtained, valid for %expiresInRaw% s", variables=True)], out=[delete("/event;1;0", "/detail;1;0")]),
               mapstep(copy("/newToken;1;0", "/accessToken;1;0"), copy("/ttl;1;0", "/expiresIn;1;0"), delete("/newToken;1;0", "/newRefresh;1;0", "/expiresInRaw;1;0", "/ttl;1;0", "/tokState;2;0", "/tokStateJson;1;0")),
           ]), comment="valid cache? otherwise refresh, otherwise password"),
    mapstep(delete("/cfg;2;0", "/tok;2;0", "/tokJson;1;0", "/now;1;0", "/nowNum;1;0", "/expiresAtNum;1;0", "/valid;1;0", "/remaining;1;0", "/tokenUrl;1;0", "/forceRefresh;1;0")),
    ], [
        invoke("pub.flow:getLastFailureCaught", out=[copy("/failureMessage;1;0", "/tokenError;1;0"), delete("/failureMessage;1;0", "/failureName;1;0", "/failure;3;0")]),
        mapstep(delete("/cfg;2;0", "/tok;2;0", "/tokJson;1;0", "/cfgJson;1;0", "/now;1;0", "/nowNum;1;0", "/expiresAtNum;1;0", "/valid;1;0", "/remaining;1;0", "/tokenUrl;1;0", "/forceRefresh;1;0", "/newToken;1;0", "/newRefresh;1;0",
                       "/expiresInRaw;1;0", "/ttl;1;0", "/tokState;2;0", "/tokStateJson;1;0", "/respJson;1;0", "/respBytes;3;0", "/httpStatus;1;0", "/resp;2;0"), comment="no secret may remain in the pipeline"),
        exit_("$flow", "FAILURE", "%tokenError%"),
    ]),
], "Provides a valid access token for an ION API access: cache (store), otherwise refresh token, otherwise password grant with the service account. The calling flow never handles credentials or expiry.")

# ------------------------------------------------------------------ ionapi.api:call
def http_api_call(comment):
    return invoke("pub.client:http",
                  inp=[setv("/headers;2;0/Authorization;1;0", "Bearer %accessToken%", variables=True), setv("/headers;2;0/Accept;1;0", "application/json"),
                       copy("/contentType;1;0", "/headers;2;0/Content-Type;1;0"), copy("/body;1;0", "/data;2;0/string;1;0"), setv("/loadAs;1;0", "bytes"), setv("/throwExceptionOnHttp401;1;0", "false"), setv("/timeout;1;0", "30000")],
                  out=[copy("/header;2;0/status;1;0", "/httpStatus;1;0"), copy("/header;2;0/statusMessage;1;0", "/httpMessage;1;0"), copy("/body;2;0/bytes;3;0", "/respBytes;3;0"), [d for d in HTTP_CLEAN if d["field"] not in ("/url;1;0", "/method;1;0")]], comment=comment)

API_CALL = service("ionapi.api:call", PKG, sig(field("alias"), field("method"), field("path"), field("body"), field("contentType")),
    sig(field("status"), field("statusMessage"), field("body"), field("json", "record"), field("tokenSource"), field("retried"), field("elapsedMs"), field("url")), [
    invoke("pub.date:currentNanoTime", out=[copy("/nanoTime;3;0", "/t0;3;0"), delete("/nanoTime;3;0")]),
    mapstep(setv("/method;1;0", "get", overwrite=False), setv("/contentType;1;0", "application/json", overwrite=False), setv("/retried;1;0", "false"), comment="default values"),
    invoke("ionapi.token:get", out=[delete("/expiresAt;1;0", "/expiresIn;1;0")], comment="token (cache / refresh / password) without exposing credentials"),
    mapstep(setv("/url;1;0", "%apiBaseUrl%%path%", variables=True)),
    http_api_call("ION API call with Authorization: Bearer"),
    body_to_string("/respBody;1;0"), mapstep(delete("/respBytes;3;0")),
    branch("/httpStatus", ("401", [
        invoke("ionapi.token:get", inp=[setv("/forceRefresh;1;0", "true")], out=[delete("/expiresAt;1;0", "/expiresIn;1;0", "/forceRefresh;1;0")], comment="401: token revoked or expired server side, re-authenticating"),
        mapstep(setv("/retried;1;0", "true")),
        invoke("ionapi.token:logEvent", inp=[setv("/event;1;0", "retry-401"), setv("/detail;1;0", "%method% %path%: 401, new token then retry", variables=True)], out=[delete("/event;1;0", "/detail;1;0")]),
        mapstep(delete("/respBody;1;0")), http_api_call("retry with the new token"), body_to_string("/respBody;1;0"), mapstep(delete("/respBytes;3;0"))]), comment="a single retry on 401"),
    quiet(json_parse("/respBody;1;0", "/json;2;0"), comment="JSON body decoded when possible"),
    *elapsed_ms("/t0;3;0", "/elapsedMs;1;0"),
    mapstep(copy("/httpStatus;1;0", "/status;1;0"), copy("/httpMessage;1;0", "/statusMessage;1;0"), copy("/respBody;1;0", "/body;1;0"),
            delete("/httpStatus;1;0", "/httpMessage;1;0", "/respBody;1;0", "/accessToken;1;0", "/apiBaseUrl;1;0", "/contentType;1;0", "/method;1;0")),
], "Calls an ION API resource (method, path relative to the access base URL, optional body): token managed automatically, single retry after a 401.")

# ------------------------------------------------------------------ ionapi.admin
SAVE_ALIAS = service("ionapi.admin:saveAlias", PKG,
    sig(field("alias"), field("ionapiJson"), field("apiBaseUrl"), field("tokenUrl"), field("clientId"), field("clientSecret"), field("saak"), field("sask"), field("scope")),
    sig(field("ok"), field("message"), field("alias"), field("tenant"), field("apiBaseUrl"), field("tokenUrl"), field("clientId")), [
    branch("/alias", ("$null", [exit_("$flow", "FAILURE", "The access name (alias) is required")])),
    branch("/ionapiJson", ("$null", []), ("$default", [
        json_parse("/ionapiJson;1;0", "/ion;2;0"),
        mapstep(copy("/ion;2;0/ti;1;0", "/tenant;1;0"), copy("/ion;2;0/ci;1;0", "/clientId;1;0"), copy("/ion;2;0/cs;1;0", "/clientSecret;1;0"), copy("/ion;2;0/saak;1;0", "/saak;1;0"), copy("/ion;2;0/sask;1;0", "/sask;1;0"),
                copy("/ion;2;0/iu;1;0", "/iu;1;0"), copy("/ion;2;0/pu;1;0", "/pu;1;0"), copy("/ion;2;0/ot;1;0", "/ot;1;0"), delete("/ion;2;0"),
                comment="reading the .ionapi file: ti, ci, cs, saak, sask, iu, pu, ot")]), comment=".ionapi file provided?"),
    branch("/pu", ("$null", []), ("$default", [mapstep(setv("/tokenUrl;1;0", "%pu%%ot%", variables=True, overwrite=False), comment="token URL = pu + ot")])),
    branch("/iu", ("$null", []), ("$default", [branch("/tenant", ("$null", [mapstep(setv("/apiBaseUrl;1;0", "%iu%", variables=True, overwrite=False))]), ("", [mapstep(setv("/apiBaseUrl;1;0", "%iu%", variables=True, overwrite=False))]),
                                                    ("$default", [mapstep(setv("/apiBaseUrl;1;0", "%iu%/%tenant%", variables=True, overwrite=False))]), comment="API base URL = iu / tenant")])),
    branch_expr(("%tokenUrl% == $null || %apiBaseUrl% == $null || %clientId% == $null || %clientSecret% == $null || %saak% == $null || %sask% == $null || %tokenUrl% == \"\" || %apiBaseUrl% == \"\" || %clientId% == \"\" || %clientSecret% == \"\" || %saak% == \"\" || %sask% == \"\"",
                 [exit_("$flow", "FAILURE", "Incomplete configuration: tokenUrl, apiBaseUrl, clientId, clientSecret, saak and sask are required (.ionapi file or manual entry)")])),
    now_str("/savedAt;1;0"),
    mapstep(copy("/alias;1;0", "/cfg;2;0/alias;1;0"), copy("/tenant;1;0", "/cfg;2;0/tenant;1;0"), copy("/apiBaseUrl;1;0", "/cfg;2;0/apiBaseUrl;1;0"), copy("/tokenUrl;1;0", "/cfg;2;0/tokenUrl;1;0"),
            copy("/clientId;1;0", "/cfg;2;0/clientId;1;0"), copy("/clientSecret;1;0", "/cfg;2;0/clientSecret;1;0"), copy("/saak;1;0", "/cfg;2;0/saak;1;0"), copy("/sask;1;0", "/cfg;2;0/sask;1;0"),
            copy("/scope;1;0", "/cfg;2;0/scope;1;0"), copy("/savedAt;1;0", "/cfg;2;0/savedAt;1;0")),
    json_string("/cfg;2;0", "/cfgJson;1;0"),
    store_set("ionapi.alias.%alias%", "/cfgJson;1;0"),
    store_remove("ionapi.token.%alias%"),
    invoke("ionapi.token:logEvent", inp=[setv("/event;1;0", "config"), setv("/detail;1;0", "access saved (%tokenUrl%)", variables=True)], out=[delete("/event;1;0", "/detail;1;0")]),
    mapstep(setv("/ok;1;0", "true"), setv("/message;1;0", "Access saved; credentials are encrypted in the Integration Server store"),
            delete("/cfg;2;0", "/cfgJson;1;0", "/ionapiJson;1;0", "/clientSecret;1;0", "/sask;1;0", "/saak;1;0", "/scope;1;0", "/pu;1;0", "/iu;1;0", "/ot;1;0", "/savedAt;1;0")),
], "Saves an ION API access from the .ionapi file (or entered fields): secrets go into the encrypted IS store, nothing else to configure.")

DELETE_ALIAS = service("ionapi.admin:deleteAlias", PKG, sig(field("alias")), sig(field("ok")), [
    store_remove("ionapi.alias.%alias%"), store_remove("ionapi.token.%alias%"),
    invoke("ionapi.token:logEvent", inp=[setv("/event;1;0", "config"), setv("/detail;1;0", "access deleted")], out=[delete("/event;1;0", "/detail;1;0")]),
    mapstep(setv("/ok;1;0", "true")),
], "Deletes an access and its token.")

LIST_ALIASES = service("ionapi.admin:listAliases", PKG, sig(), sig(field("serverTime"), field("aliases", "record", 1), field("events", "record", 1)), [
    now_str("/serverTime;1;0"), now_str("/serverTimeNum;1;0", DTN),
    invoke("ionapi.store:list", out=[copy("/keys;2;1", "/allKeys;2;1"), delete("/keys;2;1")]),
    loop("/allKeys", None,
         invoke("pub.string:indexOf", inp=[copy("/allKeys;2;0/name;1;0", "/inString;1;0"), setv("/subString;1;0", "ionapi.alias.")], out=[copy("/value;1;0", "/pos;1;0"), delete("/value;1;0", "/inString;1;0", "/subString;1;0")]),
         branch("/pos", ("0", [
             invoke("ionapi.store:get", inp=[copy("/allKeys;2;0/name;1;0", "/key;1;0")], out=[copy("/value;1;0", "/cfgJson;1;0"), delete("/key;1;0", "/value;1;0")]),
             json_parse("/cfgJson;1;0", "/cfg;2;0"),
             mapstep(copy("/cfg;2;0/alias;1;0", "/entry;2;0/alias;1;0"), copy("/cfg;2;0/tenant;1;0", "/entry;2;0/tenant;1;0"), copy("/cfg;2;0/apiBaseUrl;1;0", "/entry;2;0/apiBaseUrl;1;0"),
                     copy("/cfg;2;0/tokenUrl;1;0", "/entry;2;0/tokenUrl;1;0"), copy("/cfg;2;0/clientId;1;0", "/entry;2;0/clientId;1;0"), copy("/cfg;2;0/saak;1;0", "/entry;2;0/saak;1;0"),
                     copy("/cfg;2;0/scope;1;0", "/entry;2;0/scope;1;0"), copy("/cfg;2;0/savedAt;1;0", "/entry;2;0/savedAt;1;0"), comment="never the secrets"),
             invoke("ionapi.store:get", inp=[setv("/key;1;0", "ionapi.token.%cfg/alias%", variables=True)], out=[copy("/value;1;0", "/tokJson;1;0"), delete("/key;1;0", "/value;1;0")]),
             branch("/tokJson", ("$null", []), ("$default", [
                 json_parse("/tokJson;1;0", "/tok;2;0"),
                 mapstep(setv("/entry;2;0/tokenExpiresIn;1;0", "0")),
                 branch_expr(("%tok/expiresAtNum% > %serverTimeNum%", [
                     invoke("pub.date:calculateDateDifference", inp=[copy("/serverTime;1;0", "/startDate;1;0"), copy("/tok;2;0/expiresAt;1;0", "/endDate;1;0"), setv("/startDatePattern;1;0", DT), setv("/endDatePattern;1;0", DT)],
                            out=[copy("/dateDifferenceSeconds;1;0", "/entry;2;0/tokenExpiresIn;1;0"), delete("/dateDifferenceSeconds;1;0", "/dateDifferenceMinutes;1;0", "/dateDifferenceHours;1;0", "/dateDifferenceDays;1;0", "/startDate;1;0", "/endDate;1;0", "/startDatePattern;1;0", "/endDatePattern;1;0")])])),
                 mapstep(copy("/tok;2;0/expiresAt;1;0", "/entry;2;0/tokenExpiresAt;1;0"), copy("/tok;2;0/obtainedAt;1;0", "/entry;2;0/tokenObtainedAt;1;0"), copy("/tok;2;0/source;1;0", "/entry;2;0/tokenSource;1;0"),
                         copy("/tok;2;0/expiresIn;1;0", "/entry;2;0/tokenLifetime;1;0"), delete("/tok;2;0"))])),
             invoke("pub.list:appendToDocumentList", inp=[copy("/aliases;2;1", "/toList;2;1"), copy("/entry;2;0", "/fromItem;2;0")], out=[copy("/toList;2;1", "/aliases;2;1"), delete("/toList;2;1", "/fromItem;2;0")]),
             mapstep(delete("/entry;2;0", "/cfg;2;0", "/cfgJson;1;0", "/tokJson;1;0"))])),
         mapstep(delete("/pos;1;0")), comment="one entry per ionapi.alias.* key"),
    store_get("ionapi.events", "/evJson;1;0"),
    branch("/evJson", ("$null", []), ("$default", [json_parse("/evJson;1;0", "/journal;2;0"), mapstep(copy("/journal;2;0/events;2;1", "/events;2;1"), delete("/journal;2;0"))])),
    mapstep(delete("/allKeys;2;1", "/evJson;1;0", "/serverTimeNum;1;0")),
], "Lists the configured accesses (without secrets), their token state and the event journal.")

TEST_ALIAS = service("ionapi.admin:testAlias", PKG, sig(field("alias")), sig(field("ok"), field("message"), field("tokenSource"), field("expiresIn"), field("tokenPreview"), field("elapsedMs")), [
    invoke("pub.date:currentNanoTime", out=[copy("/nanoTime;3;0", "/t0;3;0"), delete("/nanoTime;3;0")]),
    *try_catch([
        invoke("ionapi.token:get", inp=[setv("/forceRefresh;1;0", "true")], out=[delete("/forceRefresh;1;0", "/expiresAt;1;0", "/apiBaseUrl;1;0")], comment="forced authentication"),
        invoke("pub.string:substring", inp=[copy("/accessToken;1;0", "/inString;1;0"), setv("/beginIndex;1;0", "0"), setv("/endIndex;1;0", "14")], out=[copy("/value;1;0", "/tokenPreview;1;0"), delete("/value;1;0", "/inString;1;0", "/beginIndex;1;0", "/endIndex;1;0")]),
        mapstep(setv("/ok;1;0", "true"), setv("/message;1;0", "Token obtained (%tokenSource%), valid for %expiresIn% s", variables=True), delete("/accessToken;1;0")),
    ], [
        invoke("pub.flow:getLastFailureCaught", out=[copy("/failureMessage;1;0", "/message;1;0"), delete("/failureMessage;1;0", "/failureName;1;0", "/failure;3;0")]),
        mapstep(setv("/ok;1;0", "false"), delete("/tokenError;1;0", "/accessToken;1;0", "/apiBaseUrl;1;0", "/tokenSource;1;0")),
        invoke("ionapi.token:logEvent", inp=[setv("/event;1;0", "error"), copy("/message;1;0", "/detail;1;0")], out=[delete("/event;1;0", "/detail;1;0")]),
    ]),
    *elapsed_ms("/t0;3;0", "/elapsedMs;1;0"),
], "Tests an access: obtains a token with the service account and returns a readable diagnostic.")

# ------------------------------------------------------------------ IonApiMock: fake token server + fake M3 (not deployed, see mock/ion_mock.py)
CLIENT_ID, CLIENT_SECRET, SAAK, SASK = "demo-client-id", "demo-client-secret", "DEMO#saak-service-account", "sask-demo-secret"

ISSUE = [
    invoke("pub.date:currentNanoTime", out=[copy("/nanoTime;3;0", "/nano;3;0"), delete("/nanoTime;3;0")]),
    invoke("pub.string:objectToString", inp=[copy("/nano;3;0", "/object;3;0")], out=[copy("/string;1;0", "/nanoStr;1;0"), delete("/string;1;0", "/object;3;0", "/nano;3;0")]),
    mapstep(setv("/token;1;0", "ion-%nanoStr%", variables=True), setv("/rtoken;1;0", "ionr-%nanoStr%", variables=True)),
    now_str("/now;1;0"),
    invoke("pub.date:incrementDate", inp=[copy("/now;1;0", "/startDate;1;0"), setv("/startDatePattern;1;0", DT), setv("/endDatePattern;1;0", DT), copy("/ttl;1;0", "/addSeconds;1;0")],
           out=[copy("/endDate;1;0", "/expiresAt;1;0"), delete("/endDate;1;0", "/startDate;1;0", "/startDatePattern;1;0", "/endDatePattern;1;0", "/addSeconds;1;0")]),
    store_set("ionapimock.token.%token%", "/expiresAt;1;0"),
    store_set("ionapimock.refresh.%rtoken%", "/now;1;0"),
    mapstep(copy("/token;1;0", "/resp;2;0/access_token;1;0"), copy("/rtoken;1;0", "/resp;2;0/refresh_token;1;0"), setv("/resp;2;0/token_type;1;0", "Bearer"), copy("/ttl;1;0", "/resp;2;0/expires_in;1;0")),
    json_string("/resp;2;0", "/respJson;1;0"),
    respond_json("/respJson;1;0"),
    mapstep(delete("/token;1;0", "/rtoken;1;0", "/nanoStr;1;0", "/now;1;0", "/expiresAt;1;0", "/respJson;1;0", "/resp;2;0")),
]

MOCK_TOKEN = service("ionapimock.sso:token", MOCK, sig(field("grant_type"), field("username"), field("password"), field("client_id"), field("client_secret"), field("refresh_token"), field("scope")), sig(), [
    mapstep(copy("/password;1;0", "/saskIn;1;0"), delete("/password;1;0"), comment="frees the name 'password' used by the store"),
    store_get("ionapimock.ttl", "/ttl;1;0"),
    mapstep(setv("/ttl;1;0", "90", overwrite=False), comment="lifetime of issued tokens (adjustable, 90 s by default for the demo)"),
    branch_expr(
        (f'%client_id% != "{CLIENT_ID}" || %client_secret% != "{CLIENT_SECRET}"', reject("401", '{"error":"invalid_client","error_description":"incorrect client id / secret"}')),
        (f'%grant_type% == "password" && %username% != "{SAAK}"', reject("401", '{"error":"invalid_grant","error_description":"unknown service account (saak)"}')),
        (f'%grant_type% == "password" && %saskIn% != "{SASK}"', reject("401", '{"error":"invalid_grant","error_description":"incorrect service account secret (sask)"}')),
        ('%grant_type% == "refresh_token"', [store_get("ionapimock.refresh.%refresh_token%", "/rt;1;0"),
                                             branch("/rt", ("$null", reject("401", '{"error":"invalid_grant","error_description":"unknown refresh token"}')), ("$default", ISSUE))]),
        ('%grant_type% == "password"', ISSUE),
        ("$default", reject("400", '{"error":"unsupported_grant_type"}')),
        comment="simulated token server: password and refresh_token grants"),
    mapstep(delete("/saskIn;1;0", "/ttl;1;0", "/rt;1;0", "/client_secret;1;0", "/username;1;0", "/grant_type;1;0", "/client_id;1;0", "/refresh_token;1;0", "/scope;1;0")),
], "Fake ION token server (password grant with a service account, refresh token, short-lived tokens to show the renewal).")

def bearer_check():
    return [
        invoke("pub.flow:getTransportInfo", out=[copy("/transport;4;0;pub.flow:transportInfo/http;2;0/requestHdrs;2;0/Authorization;1;0", "/authHdr;1;0"), delete("/transport;4;0;pub.flow:transportInfo")]),
        branch("/authHdr", ("$null", reject("401", '{"error":"invalid_token","error_description":"missing Authorization: Bearer"}'))),
        invoke("pub.string:substring", inp=[copy("/authHdr;1;0", "/inString;1;0"), setv("/beginIndex;1;0", "7")], out=[copy("/value;1;0", "/token;1;0"), delete("/value;1;0", "/inString;1;0", "/beginIndex;1;0")]),
        store_get("ionapimock.token.%token%", "/expiresAt;1;0"),
        branch("/expiresAt", ("$null", reject("401", '{"error":"invalid_token","error_description":"unknown token"}'))),
        now_str("/now;1;0"),
        invoke("pub.date:calculateDateDifference", inp=[copy("/now;1;0", "/startDate;1;0"), copy("/expiresAt;1;0", "/endDate;1;0"), setv("/startDatePattern;1;0", DT), setv("/endDatePattern;1;0", DT)],
               out=[copy("/dateDifferenceSeconds;1;0", "/remaining;1;0"), delete("/dateDifferenceSeconds;1;0", "/dateDifferenceMinutes;1;0", "/dateDifferenceHours;1;0", "/dateDifferenceDays;1;0", "/startDate;1;0", "/endDate;1;0", "/startDatePattern;1;0", "/endDatePattern;1;0")]),
        branch_expr(("%remaining% <= 0", reject("401", '{"error":"expired_token","error_description":"expired token"}'))),
        mapstep(delete("/authHdr;1;0", "/token;1;0", "/expiresAt;1;0", "/now;1;0", "/remaining;1;0")),
    ]

MOCK_CUSTOMER = service("ionapimock.api:customer", MOCK, sig(field("CUNO")), sig(), [
    *bearer_check(),
    mapstep(setv("/CUNO;1;0", "C000001", overwrite=False),
            setv("/respJson;1;0", '{"results":[{"transaction":"GetBasicData","records":[{"CUNO":"%CUNO%","CUNM":"Demo customer %CUNO%","CUA1":"12 Farm Road","TOWN":"Rennes","CSCD":"FR","STAT":"20","CUCL":"FARM"}]}]}', variables=True)),
    respond_json("/respJson;1;0"),
    mapstep(delete("/respJson;1;0", "/CUNO;1;0")),
], "Fake M3: GetBasicData of a customer (requires a valid Bearer token).")

MOCK_SETTTL = service("ionapimock.admin:setTtl", MOCK, sig(field("seconds")), sig(field("ok"), field("seconds")), [
    mapstep(setv("/seconds;1;0", "90", overwrite=False)), store_set("ionapimock.ttl", "/seconds;1;0"), mapstep(setv("/ok;1;0", "true")),
], "Sets the lifetime of the tokens issued by the fake server (renewal demo).")

MOCK_GETTTL = service("ionapimock.admin:getTtl", MOCK, sig(), sig(field("seconds")), [
    store_get("ionapimock.ttl", "/seconds;1;0"), mapstep(setv("/seconds;1;0", "90", overwrite=False)),
], "Current token lifetime of the fake server.")

MOCK_URL = "http://localhost:8085"
DEMO_IONAPI = {"ti": "DEMO", "cn": "Demo service account", "dt": "12", "ci": CLIENT_ID, "cs": CLIENT_SECRET, "iu": MOCK_URL,
               "pu": MOCK_URL + "/DEMO/as/", "oa": "authorization.oauth2", "ot": "token.oauth2", "or": "revoke_token.oauth2", "saak": SAAK, "sask": SASK}
M3_PATH = "/M3/m3api-rest/v2/execute/CRS610MI/GetBasicData"


def deploy_all(m):
    ensure_package(m, PKG, ["ionapi", "ionapi.store", "ionapi.token", "ionapi.api", "ionapi.admin"])
    ok = deploy(m, PKG, [STORE_SET, STORE_GET, STORE_REMOVE, STORE_LIST, LOG_EVENT, TOKEN_GET, API_CALL, SAVE_ALIAS, DELETE_ALIAS, LIST_ALIASES, TEST_ALIAS])
    # the ION API simulator is a standalone server (mock/ion_mock.py): the IS intercepts every inbound Authorization: Bearer
    json.dump(DEMO_IONAPI, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "demo.ionapi"), "w"), indent=2)
    return ok


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


import urllib.request

def mock_ttl(seconds):
    urllib.request.urlopen(urllib.request.Request(MOCK_URL + "/admin/ttl", data=f"seconds={seconds}".encode(), method="POST"), timeout=5).read()


def tests(m):
    try:
        urllib.request.urlopen(MOCK_URL + "/admin/ttl", timeout=3).read()
    except Exception:
        sys.exit("ION API simulator not running: start  python3 mock/ion_mock.py 8085 &")
    inv(m, "ionapi.store:set", {"key": "ionapi.selftest", "value": "coucou"})
    r = inv(m, "ionapi.store:get", {"key": "ionapi.selftest"}); assert r and r.get("value") == "coucou", "store failed"
    inv(m, "ionapi.store:list", maxlen=200); inv(m, "ionapi.store:remove", {"key": "ionapi.selftest"})
    mock_ttl(90)
    inv(m, "ionapi.admin:saveAlias", {"alias": "demo", "ionapiJson": json.dumps(DEMO_IONAPI)})
    inv(m, "ionapi.admin:testAlias", {"alias": "demo"})
    r = inv(m, "ionapi.api:call", {"alias": "demo", "method": "get", "path": M3_PATH + "?CUNO=C000042"}, 400); assert r and r.get("status") == "200", "call failed"
    r = inv(m, "ionapi.api:call", {"alias": "demo", "path": M3_PATH + "?CUNO=C000043"}, 200); assert r and r.get("tokenSource") == "cache", "cache failed"
    inv(m, "ionapi.admin:listAliases", maxlen=500)
    print("--- short token (20 s): after expiry, silent re-authentication (no 401) ---")
    mock_ttl(20); inv(m, "ionapi.admin:testAlias", {"alias": "demo"})
    time.sleep(17)
    r = inv(m, "ionapi.api:call", {"alias": "demo", "path": M3_PATH + "?CUNO=C000044"}, 200); assert r and r.get("status") == "200" and r.get("tokenSource") in ("password", "refresh") and r.get("retried") == "false", "re-authentication failed"
    print("--- server-side revocation: 401 then transparent retry (retried=true) ---")
    mock_ttl(90); inv(m, "ionapi.admin:testAlias", {"alias": "demo"})
    urllib.request.urlopen(urllib.request.Request(MOCK_URL + "/admin/revoke", data=b"", method="POST"), timeout=5).read()
    r = inv(m, "ionapi.api:call", {"alias": "demo", "path": M3_PATH + "?CUNO=C000045"}, 200); assert r and r.get("status") == "200" and r.get("retried") == "true", "retry after 401 failed"
    inv(m, "ionapi.admin:saveAlias", {"alias": "bad", "ionapiJson": json.dumps(dict(DEMO_IONAPI, sask="wrong"))})
    inv(m, "ionapi.admin:testAlias", {"alias": "bad"}); inv(m, "ionapi.admin:deleteAlias", {"alias": "bad"})
    print("TESTS OK")


if __name__ == "__main__":
    what = sys.argv[1:] or ["deploy", "test"]
    m = Mcp()
    try:
        if "deploy" in what and not deploy_all(m): sys.exit(1)
        if "test" in what: tests(m)
    finally:
        m.close()
