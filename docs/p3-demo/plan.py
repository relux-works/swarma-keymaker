#!/usr/bin/env python3
"""Offline, inert P3 command planner. Never executes the commands it describes."""
import argparse
import json
import re
import sys
from pathlib import PurePosixPath

KEYMAKER = "a713cc346db980e0a97affe3e5466d2ca4dc60b0"
REGISTRAR = "4494323068bb969a0c3c14b2e44e174217fc7c56"
REGISTRAR_HASH = "8b3c3f18d71a8350de406e6dae2bf58d9073c0af371c5143d61cadac4cde2e7b"
LIMIT = 65536


class Invalid(ValueError):
    pass


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Invalid("duplicate member")
        result[key] = value
    return result


def load(stream):
    raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise Invalid("manifest exceeds 65536 bytes")
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid("non-JSON number")))
    except (ValueError, UnicodeError, RecursionError):
        raise Invalid("invalid manifest JSON") from None


def members(value, expected):
    if type(value) is not dict or set(value) != set(expected.split()):
        raise Invalid("manifest members differ from template")


def inspect(m):
    """Validate shape/public references; do not authenticate referenced evidence."""
    missing = []

    def text(value, field, pattern=None):
        if value is None or (type(value) is str and
                             (not value or "REPLACE" in value or "<" in value)):
            missing.append(field)
            return False
        if (type(value) is not str or len(value) > 4096 or
                any(ord(c) < 32 or ord(c) > 126 for c in value) or
                (pattern and not re.fullmatch(pattern, value))):
            raise Invalid("invalid public field: " + field)
        return True

    def path(value, field):
        if text(value, field):
            p = PurePosixPath(value)
            if (not p.is_absolute() or str(p) != value or value == "/" or
                    value.startswith("//") or ".." in p.parts):
                raise Invalid("invalid absolute path: " + field)

    def uid(value, field):
        if value is None:
            missing.append(field)
        elif type(value) is not int or not 1 <= value <= 4294967294:
            raise Invalid("invalid UID: " + field)

    members(m, "schema release evidence operator enrollment accounts")
    if type(m["schema"]) is not int or m["schema"] != 1:
        raise Invalid("unsupported manifest schema")
    r = m["release"]
    members(r, "option tag keymaker_commit registrar_commit keymaker_sha256 registrar_sha256")
    if (r["option"], r["tag"], r["keymaker_commit"], r["registrar_commit"], r["registrar_sha256"]) != (
            "B", "v0.1.0", KEYMAKER, REGISTRAR, REGISTRAR_HASH):
        raise Invalid("release identity differs from assigned source pins")
    h = r["keymaker_sha256"]
    if text(h, "release.keymaker_sha256", r"[0-9a-f]{64}") and not h.startswith("f336ee8c"):
        raise Invalid("Keymaker digest does not match supplied prefix")
    ev = m["evidence"]
    members(ev, "ivan_release_key_decision platform_release_key_fingerprint signed_tags two_independent_builds zero_called_vulnerabilities vm_operator_approval vm_available precreated_accounts service_layout q6_root_procedure trusted_time ivan_first_signed_enrollment operator_approval uid_map name_registry")
    for key, value in ev.items():
        text(value, "evidence." + key,
             r"SHA256:[A-Za-z0-9+/]{43}" if key == "platform_release_key_fingerprint" else None)
    op = m["operator"]
    members(op, "uid generation")
    uid(op["uid"], "operator.uid")
    text(op["generation"], "operator.generation", r"[0-9a-f]{32}")
    en = m["enrollment"]
    members(en, "config operator_approval_file object_format signed_revision state_sha256 mode state_evidence")
    path(en["config"], "enrollment.config")
    path(en["operator_approval_file"], "enrollment.operator_approval_file")
    fmt = en["object_format"]
    if fmt is None:
        missing.append("enrollment.object_format")
    elif fmt not in ("sha1", "sha256"):
        raise Invalid("unsupported enrollment object format")
    text(en["signed_revision"], "enrollment.signed_revision",
         r"[0-9a-f]{64}" if fmt == "sha256" else r"[0-9a-f]{40}")
    text(en["state_sha256"], "enrollment.state_sha256", r"[0-9a-f]{64}")
    if en["mode"] is None:
        missing.append("enrollment.mode")
    elif en["mode"] not in ("bootstrap", "reconcile"):
        raise Invalid("enrollment mode must be explicitly bootstrap or reconcile")
    text(en["state_evidence"], "enrollment.state_evidence")
    accounts = m["accounts"]
    if type(accounts) is not list or not 2 <= len(accounts) <= 3:
        raise Invalid("exactly two or three precreated station accounts required")
    ids, names, homes, workspaces = set(), set(), set(), set()
    for i, a in enumerate(accounts):
        members(a, "account uid generation home workspace owner names public_key_file allowed_signers_file")
        prefix = "accounts." + str(i) + "."
        text(a["account"], prefix + "account", r"[a-z_][a-z0-9_-]{0,31}")
        uid(a["uid"], prefix + "uid")
        text(a["generation"], prefix + "generation", r"[0-9a-f]{32}")
        for field in ("home", "workspace", "public_key_file", "allowed_signers_file"):
            path(a[field], prefix + field)
        if a["public_key_file"] and not a["public_key_file"].endswith(".pub"):
            raise Invalid("signing selector must name an operator-verified public .pub file")
        text(a["owner"], prefix + "owner")
        members(a["names"], "purpose product project agent")
        if a["names"]["purpose"] != "agent-identity":
            raise Invalid("register purpose must be agent-identity")
        for key, value in a["names"].items():
            text(value, prefix + "names." + key)
        for value, seen in ((a["uid"], ids), (a["account"], names),
                            (a["home"], homes), (a["workspace"], workspaces)):
            if value is not None:
                if value in seen:
                    raise Invalid("station accounts, UIDs, homes and workspaces must be distinct")
                seen.add(value)
        if a["uid"] is not None and a["uid"] == op["uid"]:
            raise Invalid("operator and station UIDs must be distinct")
        if a["home"] and "REPLACE" not in a["home"]:
            for field in ("workspace", "public_key_file"):
                if a[field] and "REPLACE" not in a[field]:
                    if PurePosixPath(a["home"]) not in PurePosixPath(a[field]).parents:
                        raise Invalid("workspace and public selector must be inside station home")
    home_paths = [PurePosixPath(h) for h in homes if "REPLACE" not in h]
    for a in home_paths:
        if any(a in b.parents for b in home_paths):
            raise Invalid("station homes must not be nested")
    return missing


def plan(m):
    missing = inspect(m)
    if missing:
        return {"status": "BLOCKED_MISSING_INPUTS", "qualified": False,
                "missing": missing, "steps": []}, 3
    # Evidence strings are references for a human to verify, never authority.
    reconcile = ["/usr/local/bin/keymaker", "enrollment", "reconcile", "--config",
                 m["enrollment"]["config"]]
    if m["enrollment"]["mode"] == "bootstrap":
        reconcile.append("--bootstrap")
    reconcile += ["--confirm", m["enrollment"]["state_sha256"]]
    steps = [
        {"phase": "install", "manual": "Operator verifies release tags/builds and executes the pinned section 12.1 runbook; see README. No account creation is emitted."},
        {"phase": "enrollment", "as": "root operator; service stopped",
         "argv": reconcile},
        {"phase": "start", "manual": "Separate operator GO after all W0 gates; systemd runs keymaker serve --config /etc/swarma-keymaker/config.json as the service UID. Never run serve as root."},
        {"phase": "helper-approval", "manual": "The landed serve helper uses the explicit OperatorReconciler. Independently reconcile the live startup challenge and complete state, publish the protected startup_id/state_sha256 decision at enrollment.operator_approval_file, then operator-controlled SIGHUP retries loading. The CLI one-use receipt is not this approval; see README."},
    ]
    # IDs are illustrative, deterministic, and NOT available for a second live run.
    # A live caller allocates fresh IDs, durably records them, and retains them on retry.
    for i, a in enumerate(m["accounts"]):
        hello = {"method": "hello", "request_id": format(2*i+1, "032x"), "versions": [1]}
        register = {"method": "register", "params": {
            "target_uid": a["uid"], "target_generation": a["generation"],
            "owner": a["owner"], "names": a["names"], "lifetime": "persistent"},
            "request_id": format(2*i+2, "032x"), "timeout_ms": 2000}
        steps.append({"phase": "binding", "as": "configured operator UID/generation",
                      "socket": "/run/swarma-keymaker/control.sock",
                      "illustrative_only": True, "messages": [hello, register]})
        steps.append({"phase": "sign", "as": a["account"], "cwd": a["workspace"],
                      "environment": {"SSH_AUTH_SOCK": "/run/swarma-keymaker/agent.sock"},
                      "argv": ["git", "-c", "core.hooksPath=/dev/null", "-c", "gpg.format=ssh",
                               "-c", "user.signingkey=" + a["public_key_file"],
                               "commit", "--allow-empty", "-S", "-m", "P3 isolated VM demo"]})
        steps.append({"phase": "verify", "as": "independent verifier",
                      "cwd": a["workspace"],
                      "argv": ["git", "-c", "gpg.format=ssh", "-c",
                               "gpg.ssh.allowedSignersFile=" + a["allowed_signers_file"],
                               "verify-commit", "HEAD"]})
    return {"status": "UNEXECUTED_PLAN_REQUIRES_OPERATOR_VERIFICATION", "qualified": False,
            "evidence_authenticated": False, "steps": steps}, 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="public-only JSON manifest; never put secrets here")
    args = parser.parse_args()
    try:
        with open(args.manifest, "rb") as stream:
            result, code = plan(load(stream))
    except (OSError, Invalid, TypeError, OverflowError, RecursionError):
        # Do not echo input bytes, values, exception text or private paths.
        print('{"status":"INVALID_MANIFEST","qualified":false}', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
