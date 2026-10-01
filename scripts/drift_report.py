#!/usr/bin/env python3
"""Summarize `terraform show -json <planfile>` into a drift triage report.

    drift_report.py plan.json [--format text|json] [--max-value-len 160]

Why one *normal* plan (not -refresh-only): a normal plan carries both halves we need.
  resource_drift    = what changed in the cloud since the last apply (reality vs state)
  resource_changes  = what apply would do to make reality match the code (code vs refreshed state)
Intersecting the two separates attributes where reality moved (drift: codify candidates)
from attributes where the code moved ahead of reality (an unapplied change: NOT drift,
do not roll it back without asking).

Secrets: values flagged sensitive by Terraform, or under secret-looking keys, are never
printed. Only "(sensitive value changed)" is shown.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _redact import is_secret_key  # noqa: E402

MISSING = object()

# Pre-filters, not verdicts: they raise a [REVIEW] flag so a human looks before we codify.
SEC_TYPE = re.compile(
    r"(iam|_policy|_role|role_assignment|security_group|firewall|nsg|network_security|_acl|"
    r"public_access|encryption|_kms|key_vault|secret|waf|bucket_policy|_trust|"
    r"okta_.*(policy|rule|authenticator|network_zone|group_role|admin|app_signon|trusted_origin)|"
    r"google_.*_iam_|cloudtrail|guardduty|config_)", re.I)
SEC_PATH = re.compile(r"(ingress|egress|cidr|source_address|source_ranges|public|encrypt|kms|logging|"
                      r"mfa|principal|acl|policy|permission|role|allow|deny|trusted|ssl|tls|https)", re.I)
WORLD = re.compile(r"(0\.0\.0\.0/0|::/0|\"\*\"|^\*$|allUsers|allAuthenticatedUsers|Internet)")


# --------------------------------------------------------------------------- flatten / diff
def flatten(v, prefix=""):
    if isinstance(v, dict) and v:
        for k, x in v.items():
            yield from flatten(x, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(v, list) and v:
        for i, x in enumerate(v):
            yield from flatten(x, f"{prefix}[{i}]")
    else:
        yield prefix, v


def ancestors(p):
    out = [p]
    while True:
        m = re.search(r"(\.[^.\[\]]+|\[\d+\])$", p)
        if not m:
            break
        p = p[:m.start()]
        out.append(p)
    return out


def flagged_paths(mask):
    """Paths where a Terraform sensitivity/unknown mask is true."""
    if mask is True:
        return {""}
    return {p for p, v in flatten(mask or {}) if v is True}


def covered(path, flagged):
    return any(a in flagged for a in ancestors(path)) or "" in flagged


def attr_diff(before, after, unknown, sens):
    fb, fa = dict(flatten(before or {})), dict(flatten(after or {}))
    out = {}
    for p in sorted(set(fb) | set(fa)):
        if covered(p, unknown):
            continue
        b, a = fb.get(p, MISSING), fa.get(p, MISSING)
        if b == a:
            continue
        # skip {} vs {a: 1} style noise: the child paths carry the real change
        if (b in ({}, []) and any(q.startswith((p + ".", p + "[")) for q in fa)) or \
           (a in ({}, []) and any(q.startswith((p + ".", p + "[")) for q in fb)):
            continue
        out[p] = (b, a, covered(p, sens) or _secret_path(p))
    return out


def _secret_path(path):
    last = re.sub(r"\[\d+\]$", "", path).split(".")[-1]
    return is_secret_key(last)


# --------------------------------------------------------------------------- rendering
def render(v, secret, maxlen):
    if v is MISSING:
        return "<absent>"
    if secret:
        return "<sensitive>"
    s = json.dumps(v, sort_keys=True)
    return s if len(s) <= maxlen else s[:maxlen] + f"...(+{len(s) - maxlen} chars)"


def review_reasons(rtype, attrs):
    reasons = []
    if SEC_TYPE.search(rtype):
        reasons.append("security-relevant resource type")
    for path, d in attrs.items():
        if SEC_PATH.search(path):
            reasons.append(f"security-relevant attribute `{path}`")
            break
    for d in attrs.values():
        if not d["sensitive"] and WORLD.search(json.dumps(d["reality"])):
            reasons.append("reality contains a world-open / wildcard value")
            break
    return reasons


# --------------------------------------------------------------------------- core
def analyze(plan, maxlen):
    drift = {}
    for rd in plan.get("resource_drift") or []:
        ch = rd["change"]
        drift[rd["address"]] = {
            "actions": ch.get("actions", []),
            "diff": attr_diff(ch.get("before"), ch.get("after"), set(),
                              flagged_paths(ch.get("before_sensitive")) | flagged_paths(ch.get("after_sensitive"))),
        }

    rep = {k: [] for k in ("drift_caused", "code_ahead", "gone_from_cloud", "in_code_not_in_cloud",
                           "in_state_not_in_code", "already_consistent")}
    seen = set()
    for rc in plan.get("resource_changes") or []:
        addr, rtype, ch = rc["address"], rc.get("type", ""), rc["change"]
        acts = ch.get("actions", [])
        seen.add(addr)
        d = drift.get(addr)
        base = {"address": addr, "type": rtype, "actions": acts}

        if acts == ["no-op"] or acts == ["read"]:
            if d and d["diff"]:
                rep["already_consistent"].append({**base, "note": "cloud changed outside Terraform but the "
                                                  "code already says this; only state was stale",
                                                  "changed_paths": sorted(d["diff"])})
            continue
        if acts == ["create"]:
            key = "gone_from_cloud" if (d and d["actions"] == ["delete"]) else "in_code_not_in_cloud"
            rep[key].append(base)
            continue
        if acts == ["delete"]:
            rep["in_state_not_in_code"].append(base)
            continue

        # update, or replace (delete+create): per-attribute split
        unknown = flagged_paths(ch.get("after_unknown"))
        sens = flagged_paths(ch.get("before_sensitive")) | flagged_paths(ch.get("after_sensitive"))
        plan_diff = attr_diff(ch.get("before"), ch.get("after"), unknown, sens)
        drift_attrs, ahead_attrs = {}, {}
        for path, (reality, code, secret) in plan_diff.items():
            entry = {"path": path, "reality": reality, "code": code, "sensitive": secret}
            if d and path in d["diff"]:
                entry["last_applied"] = d["diff"][path][0]
                drift_attrs[path] = entry
            else:
                ahead_attrs[path] = entry
        replace = "delete" in acts and "create" in acts
        if drift_attrs:
            rep["drift_caused"].append({**base, "replace": replace,
                                        "replace_paths": ch.get("replace_paths") or [],
                                        "review_reasons": review_reasons(rtype, drift_attrs),
                                        "attributes": list(drift_attrs.values())})
        if ahead_attrs:
            rep["code_ahead"].append({**base, "replace": replace, "attributes": list(ahead_attrs.values())})

    # drift on resources that no longer appear in resource_changes (removed from config)
    for addr, d in drift.items():
        if addr not in seen and d["actions"] == ["delete"]:
            rep["gone_from_cloud"].append({"address": addr, "type": "", "actions": d["actions"]})

    for sect in ("drift_caused", "code_ahead"):
        for r in rep[sect]:
            for a in r["attributes"]:
                for k in ("reality", "code", "last_applied"):
                    if k in a:
                        a[k + "_display"] = render(a[k], a["sensitive"], maxlen)
    return rep


def to_text(rep):
    L = []
    counts = {k: len(v) for k, v in rep.items()}
    L.append("DRIFT SUMMARY  " + "  ".join(f"{k}={n}" for k, n in counts.items()))
    L.append("")

    L.append("== DRIFT-CAUSED: reality moved, code did not. Candidates to codify. ==")
    for r in rep["drift_caused"]:
        tag = "[REVIEW] " if r["review_reasons"] else ""
        rep_note = "  (REPLACE would be forced)" if r["replace"] else ""
        L.append(f"{tag}{r['address']}{rep_note}")
        for why in r["review_reasons"]:
            L.append(f"    ! {why}")
        for a in r["attributes"]:
            la = f"   last applied={a['last_applied_display']}" if "last_applied_display" in a else ""
            L.append(f"    {a['path']}: reality={a['reality_display']}   code={a['code_display']}{la}")
    if not rep["drift_caused"]:
        L.append("    (none)")

    L.append("")
    L.append("== CODE AHEAD: code differs from reality but the cloud did NOT drift. Likely an")
    L.append("   unapplied change. Do not roll back without asking. ==")
    for r in rep["code_ahead"]:
        L.append(f"{r['address']}")
        for a in r["attributes"]:
            L.append(f"    {a['path']}: reality={a['reality_display']}   code={a['code_display']}")
    if not rep["code_ahead"]:
        L.append("    (none)")

    for key, title in (
        ("gone_from_cloud", "GONE FROM CLOUD: in code and state, deleted outside Terraform. Ask: remove from code or recreate?"),
        ("in_code_not_in_cloud", "IN CODE, NOT IN CLOUD: never applied or pending creation. Not drift."),
        ("in_state_not_in_code", "IN STATE, NOT IN CODE: still exists in the cloud, code block removed. Not drift."),
        ("already_consistent", "ALREADY CONSISTENT: cloud changed but the code already matches; nothing to edit."),
    ):
        L.append("")
        L.append(f"== {title} ==")
        for r in rep[key]:
            extra = f"  paths={r['changed_paths']}" if r.get("changed_paths") else ""
            L.append(f"    {r['address']}{extra}")
        if not rep[key]:
            L.append("    (none)")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plan_json")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--max-value-len", type=int, default=160)
    args = ap.parse_args()
    with open(args.plan_json) as f:
        plan = json.load(f)
    if "resource_changes" not in plan and "resource_drift" not in plan:
        print("error: not a `terraform show -json <planfile>` document", file=sys.stderr)
        return 2
    rep = analyze(plan, args.max_value_len)
    if args.format == "json":
        # raw values are removed; only masked *_display strings are emitted
        for sect in ("drift_caused", "code_ahead"):
            for r in rep[sect]:
                for a in r["attributes"]:
                    for k in ("reality", "code", "last_applied"):
                        a.pop(k, None)
        print(json.dumps(rep, indent=2))
    else:
        print(to_text(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
