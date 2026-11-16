#!/usr/bin/env python3
"""Minimal SCIM 2.0 server for Okta provisioning labs.

Run:  SCIM_TOKEN=yourtoken python3 scim_server.py
API:  /scim/v2   Dashboard: /
"""
import json
import os
import uuid
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

TOKEN = os.environ.get("SCIM_TOKEN", "")
PORT = int(os.environ.get("PORT", "5000"))
DATA_FILE = os.environ.get("DATA_FILE", "scim_data.json")
BASE = "/scim/v2"

app = Flask(__name__)
DB = {"Users": {}, "Groups": {}}


def load():
    global DB
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            DB = json.load(f)


def save():
    with open(DATA_FILE, "w") as f:
        json.dump(DB, f, indent=2)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scim(body, status=200):
    resp = Response(json.dumps(body), status=status, mimetype="application/scim+json")
    return resp


def error(status, detail, scim_type=None):
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return scim(body, status)


@app.before_request
def check_auth():
    if request.path.startswith(BASE):
        if not TOKEN:
            return error(500, "SCIM_TOKEN not set on server")
        if request.headers.get("Authorization", "") != f"Bearer {TOKEN}":
            return error(401, "Unauthorized")


def location(kind, rid):
    return request.host_url.rstrip("/").replace("http://", "https://") + f"{BASE}/{kind}/{rid}"


def with_meta(kind, res):
    out = dict(res)
    out["meta"] = {
        "resourceType": kind[:-1],
        "created": res["_created"],
        "lastModified": res["_modified"],
        "location": location(kind, res["id"]),
    }
    out.pop("_created", None)
    out.pop("_modified", None)
    return out


def apply_filter(items, flt):
    """Supports: attr eq "value" (what Okta uses)."""
    if not flt:
        return items
    parts = flt.split(None, 2)
    if len(parts) == 3 and parts[1].lower() == "eq":
        attr, val = parts[0], parts[2].strip('"')
        return [i for i in items if str(i.get(attr, "")).lower() == val.lower()]
    return items


def list_response(kind):
    flt = request.args.get("filter")
    start = max(int(request.args.get("startIndex", 1)), 1)
    count = int(request.args.get("count", 100))
    items = apply_filter(list(DB[kind].values()), flt)
    page = items[start - 1:start - 1 + count]
    return scim({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(items),
        "startIndex": start,
        "itemsPerPage": len(page),
        "Resources": [with_meta(kind, i) for i in page],
    })


# ---------- discovery ----------
@app.get(f"{BASE}/ServiceProviderConfig")
def spc():
    return scim({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken", "name": "Bearer Token",
            "description": "Authentication via bearer token",
        }],
    })


# ---------- users ----------
@app.get(f"{BASE}/Users")
def users_list():
    return list_response("Users")


@app.post(f"{BASE}/Users")
def users_create():
    body = request.get_json(force=True)
    uname = body.get("userName")
    if not uname:
        return error(400, "userName is required", "invalidValue")
    if any(u["userName"].lower() == uname.lower() for u in DB["Users"].values()):
        return error(409, "User already exists", "uniqueness")
    uid = str(uuid.uuid4())
    user = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": uid,
        "userName": uname,
        "name": body.get("name", {}),
        "emails": body.get("emails", []),
        "displayName": body.get("displayName", ""),
        "title": body.get("title", ""),
        "active": body.get("active", True),
        "_created": now(), "_modified": now(),
    }
    DB["Users"][uid] = user
    save()
    return scim(with_meta("Users", user), 201)


@app.get(f"{BASE}/Users/<uid>")
def users_get(uid):
    u = DB["Users"].get(uid)
    return scim(with_meta("Users", u)) if u else error(404, "User not found")


@app.put(f"{BASE}/Users/<uid>")
def users_put(uid):
    u = DB["Users"].get(uid)
    if not u:
        return error(404, "User not found")
    body = request.get_json(force=True)
    for k in ("userName", "name", "emails", "displayName", "title", "active"):
        if k in body:
            u[k] = body[k]
    u["_modified"] = now()
    save()
    return scim(with_meta("Users", u))


def set_path(obj, path, value):
    """Handles simple paths like active, name.givenName, and dict values."""
    if path is None:
        if isinstance(value, dict):
            for k, v in value.items():
                set_path(obj, k, v)
        return
    if "." in path:
        head, tail = path.split(".", 1)
        obj.setdefault(head, {})[tail] = value
    else:
        obj[path] = value


@app.patch(f"{BASE}/Users/<uid>")
def users_patch(uid):
    u = DB["Users"].get(uid)
    if not u:
        return error(404, "User not found")
    for op in request.get_json(force=True).get("Operations", []):
        kind = op.get("op", "").lower()
        path, value = op.get("path"), op.get("value")
        if kind in ("add", "replace"):
            if isinstance(value, str) and path == "active":
                value = value.lower() == "true"
            set_path(u, path, value)
        elif kind == "remove" and path:
            u.pop(path, None)
    u["_modified"] = now()
    save()
    return scim(with_meta("Users", u))


@app.delete(f"{BASE}/Users/<uid>")
def users_delete(uid):
    if DB["Users"].pop(uid, None) is None:
        return error(404, "User not found")
    save()
    return Response(status=204)


# ---------- groups (for Okta Push Groups) ----------
@app.get(f"{BASE}/Groups")
def groups_list():
    return list_response("Groups")


@app.post(f"{BASE}/Groups")
def groups_create():
    body = request.get_json(force=True)
    gid = str(uuid.uuid4())
    g = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": gid,
        "displayName": body.get("displayName", ""),
        "members": body.get("members", []),
        "_created": now(), "_modified": now(),
    }
    DB["Groups"][gid] = g
    save()
    return scim(with_meta("Groups", g), 201)


@app.get(f"{BASE}/Groups/<gid>")
def groups_get(gid):
    g = DB["Groups"].get(gid)
    return scim(with_meta("Groups", g)) if g else error(404, "Group not found")


@app.put(f"{BASE}/Groups/<gid>")
def groups_put(gid):
    g = DB["Groups"].get(gid)
    if not g:
        return error(404, "Group not found")
    body = request.get_json(force=True)
    g["displayName"] = body.get("displayName", g["displayName"])
    g["members"] = body.get("members", g["members"])
    g["_modified"] = now()
    save()
    return scim(with_meta("Groups", g))


@app.patch(f"{BASE}/Groups/<gid>")
def groups_patch(gid):
    g = DB["Groups"].get(gid)
    if not g:
        return error(404, "Group not found")
    for op in request.get_json(force=True).get("Operations", []):
        kind = op.get("op", "").lower()
        path, value = op.get("path"), op.get("value")
        if path == "displayName" and kind in ("add", "replace"):
            g["displayName"] = value
        elif path == "members" or (path and path.startswith("members[")):
            if kind == "add":
                g["members"].extend(value or [])
            elif kind == "replace":
                g["members"] = value or []
            elif kind == "remove":
                if path.startswith("members[value eq"):
                    mid = path.split('"')[1]
                    g["members"] = [m for m in g["members"] if m.get("value") != mid]
                else:
                    ids = {m.get("value") for m in (value or [])}
                    g["members"] = [m for m in g["members"] if m.get("value") not in ids] if ids else []
    g["_modified"] = now()
    save()
    return scim(with_meta("Groups", g))


@app.delete(f"{BASE}/Groups/<gid>")
def groups_delete(gid):
    if DB["Groups"].pop(gid, None) is None:
        return error(404, "Group not found")
    save()
    return Response(status=204)


# ---------- dashboard ----------
@app.get("/")
def dashboard():
    from html import escape
    urows = ""
    for u in DB["Users"].values():
        n = u.get("name", {}) or {}
        full = escape(f"{n.get('givenName', '')} {n.get('familyName', '')}".strip())
        active = u.get("active") in (True, "true", "True")
        status = '<span class="ok">Active</span>' if active else '<span class="bad">Inactive</span>'
        modified = escape(u.get("_modified", "").replace("T", " ").replace("Z", ""))
        urows += (f"<tr><td>{escape(u['userName'])}</td><td>{full}</td>"
                  f"<td>{escape(u.get('title', '') or '')}</td><td>{status}</td><td>{modified}</td></tr>")
    if not urows:
        urows = '<tr><td colspan="5" class="muted">No users yet</td></tr>'
    grows = "".join(
        f"<tr><td>{escape(g['displayName'])}</td><td>{len(g.get('members', []))}</td></tr>"
        for g in DB["Groups"].values()
    ) or '<tr><td colspan="2" class="muted">No groups yet</td></tr>'
    return f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5>
<title>SCIM Lab App</title>
<style>
body{{font-family:-apple-system,Helvetica,Arial,sans-serif;margin:0;padding:24px 28px;color:#222}}
h1{{margin:0 0 6px;font-size:28px}} h2{{margin:28px 0 10px;font-size:20px}}
.sub{{font-size:12px;color:#444;margin-bottom:18px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:9px 10px;text-align:left}}
th{{background:#f3f3f3}} .ok{{color:#1a7f37;font-weight:600}} .bad{{color:#c62828;font-weight:600}}
.muted{{color:#666}}
</style>
<h1>SCIM Lab App</h1>
<div class="sub">Users provisioned by Okta via SCIM 2.0. Refreshes every 5 seconds.</div>
<h2>Users</h2>
<table><tr><th>userName</th><th>Name</th><th>Title</th><th>Status</th><th>Last modified (UTC)</th></tr>{urows}</table>
<h2>Groups</h2>
<table><tr><th>Group</th><th>Members</th></tr>{grows}</table>"""


if __name__ == "__main__":
    load()
    if not TOKEN:
        print("WARNING: SCIM_TOKEN is not set; all SCIM requests will fail.")
    app.run(host="0.0.0.0", port=PORT)
