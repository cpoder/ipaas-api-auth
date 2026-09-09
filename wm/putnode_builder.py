"""Small flow service builder for the Integration Server putNode API (see flows.py for usage).

Explicit WmPath paths: /field;type;dim  (1 = String, 2 = Record, 3 = Object, 4 = RecordRef; dim 0 scalar, 1 list).
"""
import json
from xml.sax.saxutils import escape


def copy(frm, to):
    return {"type": "MAPCOPY", "from": frm, "to": to}

def setv(field, value, variables=False, overwrite=True):
    d = {"type": "MAPSET", "field": field, "overwrite": "true" if overwrite else "false", "d_enc": "XMLValues", "mapseti18n": "true",
         "data": f'<Values version="2.0"><value name="xml">{escape(value)}</value></Values>'}
    if variables:
        d["variables"] = "true"
    return d

def delete(*fields):
    return [{"type": "MAPDELETE", "field": f} for f in fields]

def flat(items):
    out = []
    for i in items:
        out.extend(i) if isinstance(i, list) else out.append(i)
    return out

def mapstep(*nodes, comment=None):
    d = {"type": "MAP", "mode": "STANDALONE", "nodes": flat(nodes)}
    if comment: d["comment"] = comment
    return d

def invoke(service, inp=(), out=(), comment=None):
    d = {"type": "INVOKE", "service": service, "validate-in": "$none", "validate-out": "$none",
         "nodes": [{"type": "MAP", "mode": "INPUT", "nodes": flat(inp)}, {"type": "MAP", "mode": "OUTPUT", "nodes": flat(out)}]}
    if comment: d["comment"] = comment
    return d

def sequence(*nodes, label=None, exit_on="FAILURE", form=None, comment=None):
    d = {"type": "SEQUENCE", "exit-on": exit_on, "nodes": flat(nodes)}
    if label is not None: d["label"] = label
    if form: d["form"] = form
    if comment: d["comment"] = comment
    return d

def try_catch(try_nodes, catch_nodes):
    return [sequence(*try_nodes, form="TRY"), sequence(*catch_nodes, form="CATCH")]

def quiet(*nodes, comment=None):
    """SEQUENCE exit-on DONE: child failures do not interrupt the flow (e.g. key missing from the store)."""
    return sequence(*nodes, exit_on="DONE", comment=comment)

def loop(in_array, out_array, *nodes, comment=None, threads=None):
    d = {"type": "LOOP", "in-array": in_array, "nodes": flat(nodes)}
    if out_array: d["out-array"] = out_array
    if threads: d["max-threads"] = str(threads); d["parallel-error-handling"] = "reportError"
    if comment: d["comment"] = comment
    return d

def branch(switch, *cases, comment=None):
    """cases: (label, [nodes]) -- BRANCH on the value of a variable."""
    d = {"type": "BRANCH", "switch": switch, "nodes": [sequence(*n, label=l) for l, n in cases]}
    if comment: d["comment"] = comment
    return d

def branch_expr(*cases, comment=None):
    """cases: (expression, [nodes]) -- BRANCH on expressions (putNode key: evaluate-labels)."""
    d = {"type": "BRANCH", "evaluate-labels": "true", "nodes": [sequence(*n, label=e) for e, n in cases]}
    if comment: d["comment"] = comment
    return d

def exit_(from_="$flow", signal="FAILURE", message=None):
    d = {"type": "EXIT", "from": from_, "signal": signal}
    if message: d["failure-message"] = message
    return d

def field(name, ftype="string", dim=0, doc=None):
    if ftype == "recref":
        return {"node_type": "record", "field_name": name, "field_type": "recref", "field_dim": str(dim), "nillable": "true", "rec_ref": doc, "rec_closed": "true"}
    if ftype == "record":
        return {"node_type": "record", "field_name": name, "field_type": "record", "field_dim": str(dim), "nillable": "true", "rec_fields": []}
    d = {"node_type": "field", "field_name": name, "field_type": ftype, "field_dim": str(dim), "nillable": "true"}
    if ftype == "object":
        d["wrapper_type"] = "java.lang.Object"
    return d

def sig(*fields):
    return {"node_type": "record", "field_type": "record", "field_dim": "0", "nillable": "true", "javaclass": "com.wm.util.Values", "rec_fields": list(fields)}

def service(ns, pkg, sig_in, sig_out, nodes, comment=""):
    return {"node_nsName": ns, "node_pkg": pkg, "node_type": "service", "svc_type": "flow", "svc_subtype": "default",
            "svc_sigtype": "java 3.5", "stateless": "yes", "pipeline_option": 1, "node_comment": comment,
            "svc_sig": {"sig_in": sig_in, "sig_out": sig_out},
            "flow": {"type": "ROOT", "version": "3.0", "cleanup": "true", "nodes": flat(nodes)}}

# ------------------------------------------------------------------ deployment
def ignore_exists(fn):
    try:
        return fn()
    except Exception as e:
        if "exist" in str(e).lower() or "already" in str(e).lower():
            return None
        raise

def ensure_package(m, pkg, folders):
    ignore_exists(lambda: m.call("package_create", {"package_name": pkg}))
    for f in folders:
        ignore_exists(lambda: m.call("folder_create", {"package": pkg, "folder_path": f}))

def node_exists(m, full):
    try:
        return bool(json.loads(m.call("node_get", {"name": full})).get("node"))
    except Exception:
        return False

def deploy(m, pkg, services, acl=None):
    """Creates/updates each service (shell then putNode), verifies with node_get, optionally assigns an ACL."""
    ok = True
    for s in services:
        full = s["node_nsName"]
        try:
            if not node_exists(m, full):
                ignore_exists(lambda: m.call("flow_service_create", {"package": pkg, "service_path": full}))
            out = m.call("put_node", {"node_data": json.dumps(s, ensure_ascii=False)})
            if out.lstrip().lower().startswith(("putnode failed", "failed", "error")):
                raise RuntimeError(out[:400])
            g = json.loads(m.call("node_get", {"name": full}))
            if (g.get("node") or {}).get("svc_type") != "flow":
                raise RuntimeError("node missing or not a flow after put_node")
            if acl:  # wm.server.access:aclAssign(target, acl) = execute ACL (the MCP tool acl_assign 2.12.0 applied nothing)
                m.call("service_invoke", {"service_path": "wm.server.access:aclAssign", "inputs": json.dumps({"target": full, "acl": acl})})
            print(f"OK  {full}" + (f" (ACL {acl})" if acl else ""))
        except Exception as e:
            ok = False
            print(f"KO  {full}: {str(e)[:500]}")
    return ok
