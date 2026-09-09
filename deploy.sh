#!/usr/bin/env bash
# Deploys the API authentication packages (idempotent). IS_HOME and WM_MCP_BIN can be overridden from the environment.
#   ./deploy.sh            -> ApiAuth (universal): simulator, package, tests, UI
#   ./deploy.sh apiauth    -> same
#   ./deploy.sh ionapi     -> IonApiClient package (Infor ION API only): simulator, package, tests, UI
#   ./deploy.sh all        -> both
set -euo pipefail
cd "$(dirname "$0")"
IS_HOME=${IS_HOME:-/home/cpo/wm12/IntegrationServer/instances/default}
curl -sf -m 5 -u Administrator:manage http://localhost:5555/invoke/wm.server/ping >/dev/null || { echo "Integration Server unreachable on :5555 (start $IS_HOME/bin/startup.sh)"; exit 1; }
ionapi() {   # ION API simulator + IonApiClient package + tests
  pgrep -f "^python3 ion_mock.py" >/dev/null || (cd mock && setsid nohup python3 ion_mock.py 8085 > ion_mock.log 2>&1 < /dev/null &)
  sleep 1
  python3 wm/ionapi_build.py deploy test
  mkdir -p "$IS_HOME/packages/IonApiClient/pub" && cp ui/ionapi/index.html "$IS_HOME/packages/IonApiClient/pub/index.html"
  echo "[ionapi] http://localhost:5555/IonApiClient/index.html"
}
apiauth() {  # universal simulator + ApiAuth package + tests + UI
  pgrep -f "^python3 auth_mock.py" >/dev/null || (cd mock && setsid nohup python3 auth_mock.py 8086 > auth_mock.log 2>&1 < /dev/null &)
  [ -f mock/is_cert.pem ] || keytool -exportcert -rfc -alias ssos -keystore "$IS_HOME/../../../common/conf/keystore.jks" -storepass manage -file mock/is_cert.pem 2>/dev/null || true
  sleep 1
  python3 wm/apiauth_build.py deploy test
  mkdir -p "$IS_HOME/packages/ApiAuth/pub" && cp ui/apiauth/index.html "$IS_HOME/packages/ApiAuth/pub/index.html"
  echo "[apiauth] http://localhost:5555/ApiAuth/index.html"
}
case "${1:-apiauth}" in
  apiauth) apiauth ;; ionapi) ionapi ;; all) apiauth; ionapi ;;
  *) echo "usage: $0 [apiauth|ionapi|all]"; exit 2 ;;
esac
