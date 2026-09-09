#!/usr/bin/env python3
"""Minimal JSON-RPC (stdio) driver for wm-mcp-server.

Usage:
  mcpcli.py tools                      # list tool names
  mcpcli.py schema <tool>              # print a tool's input schema
  mcpcli.py resources                  # list resources
  mcpcli.py resource <uri>             # read a resource (text)
  mcpcli.py call <tool> '<json args>'  # call one tool
  mcpcli.py batch <file.json>          # [{"tool":..,"args":{..}}, ...] in one session
"""
import json, os, subprocess, sys, itertools

BIN = os.environ.get("WM_MCP_BIN", "/home/cpo/wm-claude/mcp-server-rs/target/release/wm-mcp-server")
ENV = dict(os.environ,
           WM_IS_URL=os.environ.get("WM_IS_URL", "http://localhost:5555"),
           WM_IS_USER=os.environ.get("WM_IS_USER", "Administrator"),
           WM_IS_PASSWORD=os.environ.get("WM_IS_PASSWORD", "manage"),
           WM_IS_TIMEOUT=os.environ.get("WM_IS_TIMEOUT", "1800"))


class Mcp:
    def __init__(self):
        self.p = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=open(os.devnull, "w"), env=ENV, text=True, bufsize=1)
        self.ids = itertools.count(1)
        self.req("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                "clientInfo": {"name": "mcpcli", "version": "0.1"}})
        self.notify("notifications/initialized", {})

    def notify(self, method, params):
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
        self.p.stdin.flush()

    def req(self, method, params):
        i = next(self.ids)
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("server closed stdout")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == i:
                if "error" in msg:
                    raise RuntimeError(json.dumps(msg["error"]))
                return msg["result"]

    def call(self, tool, args):
        r = self.req("tools/call", {"name": tool, "arguments": args})
        texts = [c.get("text", "") for c in r.get("content", []) if c.get("type") == "text"]
        out = "\n".join(texts)
        if r.get("isError"):
            raise RuntimeError(out)
        return out

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__); return 2
    m = Mcp()
    try:
        cmd = a[0]
        if cmd == "tools":
            r = m.req("tools/list", {})
            for t in r["tools"]:
                print(t["name"])
            print(f"# {len(r['tools'])} tools", file=sys.stderr)
        elif cmd == "schema":
            r = m.req("tools/list", {})
            for t in r["tools"]:
                if t["name"] == a[1]:
                    print(json.dumps(t, indent=2, ensure_ascii=False))
        elif cmd == "resources":
            r = m.req("resources/list", {})
            for x in r["resources"]:
                print(x["uri"], "-", x.get("name", ""), "-", (x.get("description") or "")[:100])
        elif cmd == "resource":
            r = m.req("resources/read", {"uri": a[1]})
            for c in r["contents"]:
                print(c.get("text", ""))
        elif cmd == "call":
            args = json.loads(a[2]) if len(a) > 2 else {}
            print(m.call(a[1], args))
        elif cmd == "batch":
            calls = json.load(open(a[1]))
            rc = 0
            for c in calls:
                print(f"### {c['tool']} {json.dumps(c.get('args', {}), ensure_ascii=False)[:200]}")
                try:
                    print(m.call(c["tool"], c.get("args", {})))
                except Exception as e:
                    rc = 1
                    print("!! ERROR:", e)
                    if c.get("stop_on_error", True):
                        return rc
            return rc
        else:
            print(__doc__); return 2
    except Exception as e:
        print("!! ERROR:", e)
        return 1
    finally:
        m.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
