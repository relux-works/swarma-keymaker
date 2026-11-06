#!/usr/bin/env python3
"""Bounded fake-manifest and exact-source checks; no product processes or keys."""
import copy
import io
import json
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

import plan

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def fake_manifest(count=2):
    m = json.loads((HERE / "manifest.example.json").read_text())
    # Deliberately fabricated public evidence labels, not qualification receipts.
    m["release"]["keymaker_sha256"] = "f336ee8c" + "0" * 56
    m["evidence"] = {k: "FAKE-public-evidence" for k in m["evidence"]}
    m["evidence"]["platform_release_key_fingerprint"] = "SHA256:" + "A" * 43
    m["operator"] = {"uid": 31000, "generation": "a" * 32}
    m["enrollment"].update(operator_approval_file="/etc/swarma-keymaker/approval.json",
                            object_format="sha1", signed_revision="b" * 40,
                            state_sha256="c" * 64, mode="bootstrap",
                            state_evidence="FAKE-pristine-state-evidence")
    m["accounts"] = []
    for i in range(count):
        name = "fake-station-" + str(i)
        home = "/home/" + name
        m["accounts"].append({
            "account": name, "uid": 32000+i, "generation": format(i+1, "032x"),
            "home": home, "workspace": home + "/demo", "owner": "FAKE-owner",
            "names": {"purpose": "agent-identity", "product": "fake", "project": "demo", "agent": name},
            "public_key_file": home + "/bound-key.pub",
            "allowed_signers_file": "/etc/demo/" + name + ".allowed-signers"})
    return m


class Checks(unittest.TestCase):
    def test_template_blocks_with_no_effect_plan(self):
        m = json.loads((HERE / "manifest.example.json").read_text())
        result, code = plan.plan(m)
        self.assertEqual(code, 3)
        self.assertFalse(result["qualified"])
        self.assertEqual(result["steps"], [])
        for field in ("release.keymaker_sha256", "evidence.vm_available",
                      "evidence.ivan_release_key_decision", "evidence.operator_approval",
                      "evidence.uid_map", "evidence.ivan_first_signed_enrollment"):
            self.assertIn(field, result["missing"])

    def test_two_and_three_accounts_are_inert(self):
        for count in (2, 3):
            m = fake_manifest(count)
            before = copy.deepcopy(m)
            # The plan path cannot inspect inputs, run a shell, or open a socket.
            with patch("builtins.open", side_effect=AssertionError("unexpected file access")):
                result, code = plan.plan(m)
            self.assertEqual(m, before)
            self.assertEqual(code, 0)
            self.assertFalse(result["qualified"])
            self.assertFalse(result["evidence_authenticated"])
            self.assertEqual([s["phase"] for s in result["steps"]],
                             ["install", "enrollment", "start", "helper-approval"] +
                             ["binding", "sign", "verify"] * count)
            ids = []
            for s in result["steps"]:
                if s["phase"] == "binding":
                    self.assertTrue(s["illustrative_only"])
                    for msg in s["messages"]:
                        ids.append(msg["request_id"])
                        body = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
                        frame = struct.pack(">I", len(body)) + body
                        self.assertTrue(1 <= len(body) <= 65536)
                        self.assertEqual(struct.unpack(">I", frame[:4])[0], len(frame)-4)
                        self.assertEqual(json.loads(frame[4:]), msg)
                    register = s["messages"][1]
                    self.assertEqual(set(register), {"method", "params", "request_id", "timeout_ms"})
                    self.assertEqual(set(register["params"]),
                                     {"target_uid", "target_generation", "owner", "names", "lifetime"})
                    self.assertEqual(register["timeout_ms"], 2000)
                if s["phase"] == "sign":
                    self.assertIn("-S", s["argv"])
                    self.assertEqual(s["environment"]["SSH_AUTH_SOCK"], "/run/swarma-keymaker/agent.sock")
            self.assertEqual(len(ids), len(set(ids)))

    def test_restart_never_emits_bootstrap(self):
        m = fake_manifest()
        m["enrollment"]["mode"] = "reconcile"
        result, code = plan.plan(m)
        self.assertEqual(code, 0)
        self.assertNotIn("--bootstrap", result["steps"][1]["argv"])
        self.assertIn("--confirm", result["steps"][1]["argv"])
        m["enrollment"]["state_evidence"] = None
        result, code = plan.plan(m)
        self.assertEqual(code, 3)
        self.assertEqual(result["steps"], [])

    def test_every_missing_evidence_ref_blocks(self):
        m = fake_manifest()
        for key in m["evidence"]:
            with self.subTest(key=key):
                candidate = copy.deepcopy(m)
                candidate["evidence"][key] = None
                result, code = plan.plan(candidate)
                self.assertEqual(code, 3)
                self.assertEqual(result["steps"], [])

    def test_malformed_and_wrong_binding_refuse(self):
        m = fake_manifest()
        variants = []
        for count in (0, 1, 4):
            x = copy.deepcopy(m)
            x["accounts"] = fake_manifest(count)["accounts"]
            variants.append(x)
        for field, value in (("uid", 0), ("uid", True), ("uid", 4294967295),
                             ("uid", 31000), ("generation", "a" * 31),
                             ("workspace", "/tmp/foreign"), ("home", "relative"),
                             ("public_key_file", "/home/foreign/key.pub"),
                             ("home", "//home/station"),
                             ("home", "/home/../tmp"), ("public_key_file", "/private/key")):
            x = copy.deepcopy(m)
            x["accounts"][0][field] = value
            variants.append(x)
        x = copy.deepcopy(m)
        x["accounts"][1]["uid"] = x["accounts"][0]["uid"]
        variants.append(x)
        for field, value in (("keymaker_sha256", "f336ee8c"),
                             ("keymaker_sha256", "e" * 64),
                             ("keymaker_commit", "c" * 40), ("option", "A")):
            x = copy.deepcopy(m)
            x["release"][field] = value
            variants.append(x)
        x = copy.deepcopy(m)
        x["extra"] = "not permitted"
        variants.append(x)
        for candidate in variants:
            with self.assertRaises(plan.Invalid):
                plan.plan(candidate)

    def test_bounded_strict_json(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{}{}', b'\xff', b' ' * 65537):
            with self.assertRaises(plan.Invalid):
                plan.load(io.BytesIO(raw))

    def test_exact_source_cli_and_native_contract(self):
        # Source anchors from the assigned clean base, not a behavioral qualification.
        cli = (ROOT / "cmd/keymaker/main.go").read_text()
        self.assertIn('args[0] == "enrollment" && args[1] == "reconcile"', cli)
        self.assertIn('flags.String("config", ""', cli)
        self.assertIn('flags.String("confirm", ""', cli)
        self.assertIn('flags.Bool("bootstrap", false', cli)
        native = (ROOT / "internal/keymaker/native.go").read_text()
        self.assertIn('exactMembers(r.Params, "target_uid", "target_generation", "owner", "names", "lifetime")', native)
        self.assertIn('resolved.Purpose != "agent-identity"', native)
        runtime = (ROOT / "internal/keymaker/runtime_linux.go").read_text()
        self.assertIn('cfg.GenerationJournal == nil', runtime)
        self.assertIn('failure("service must be unprivileged")', runtime)
        helper = (ROOT / "internal/keymaker/registration_linux.go").read_text()
        self.assertIn('enrollment.NewOperatorReconciler(cfg.ApprovalFile, nil)', helper)
        self.assertIn('enrollment.New(cfg.EnrollmentConfig, nil, reconciler)', helper)
        approval = (ROOT / "internal/enrollment/reconcile.go").read_text()
        self.assertIn('`json:"startup_id"`', approval)
        self.assertIn('`json:"state_sha256"`', approval)
        registrar = Path("/registrar/cmd/registrar/main.go").read_text()
        self.assertIn('registrar serve --config <path> [--reconcile] [--loopback-test-http]', registrar)
        self.assertIn('flags.Bool("reconcile", false', registrar)


if __name__ == "__main__":
    unittest.main(verbosity=2)
