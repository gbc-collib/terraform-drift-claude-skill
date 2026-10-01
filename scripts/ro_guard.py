#!/usr/bin/env python3
"""Read-only command guard for the terraform-drift-reconcile skill.

Every terraform / cloud / IdP command goes through this wrapper:

    ro_guard.py [--out FILE] [--check] <command> [args...]      (a leading `--` is optional)
    ro_guard.py [--out FILE] okta GET </api/v1/...> [--max-pages N]

What it does
  * Allowlists read-only verbs per tool and fail-closes on anything else
    (exit 126, reason on stderr).
  * Blocks known secret-returning reads (get-secret-value, keyvault secret show, ...).
  * Redacts secret-looking values in JSON output before it reaches the transcript.
  * --out FILE writes (redacted) stdout to a file instead of printing it, so big
    payloads and raw `terraform show -json` never enter the conversation.

What it does NOT do
  This is defense in depth, not a security boundary. The real boundary is the
  credentials in use: run under a read-only role (AWS ReadOnlyAccess/SecurityAudit,
  Azure Reader, GCP Viewer, Okta read-only admin).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _redact import redact  # noqa: E402

DENIED = 126
MAX_STDOUT_CHARS = 30000


class Denied(Exception):
    pass


# --------------------------------------------------------------------------- helpers
def has_seq(words, seq):
    n = len(seq)
    return any(tuple(words[i:i + n]) == tuple(seq) for i in range(len(words) - n + 1))


def leading_words(args):
    """Tokens before the first flag: the command path for az / gcloud."""
    out = []
    for a in args:
        if a.startswith("-"):
            break
        out.append(a)
    return out


def flag_values(args, *names):
    vals = []
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                vals.append(args[i + 1])
            elif a.startswith(n + "="):
                vals.append(a.split("=", 1)[1])
    return vals


# --------------------------------------------------------------------------- terraform
def check_terraform(argv):
    args = argv[1:]
    opts = {"redact": True, "require_out": False}
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] in ("-version", "--version", "-help", "--help"):
            return opts
        if not args[i].startswith("-chdir="):
            raise Denied(f"unsupported global flag {args[i]!r}")
        i += 1
    if i >= len(args):
        raise Denied("no subcommand")
    sub = args[i]
    rest = [("-" + a.lstrip("-")) if a.startswith("--") else a for a in args[i + 1:]]

    if sub in ("version", "validate", "fmt", "providers", "graph", "get"):
        return opts
    if sub == "init":
        bad = {"-migrate-state", "-force-copy"} & set(rest)
        if bad:
            raise Denied(f"init {sorted(bad)} would move state between backends")
        return opts
    if sub == "plan":
        if "-lock=false" not in rest:
            raise Denied("plan must pass -lock=false (taking the state lock is a write to the backend)")
        if "-destroy" in rest:
            raise Denied("plan -destroy is not part of drift reconciliation")
        if "-refresh=false" in rest:
            raise Denied("plan -refresh=false skips the cloud reads that detect drift")
        return opts
    if sub == "show":
        if "-json" in rest:
            # Raw JSON contains unmasked values. Must go to a file; drift_report.py masks them.
            opts.update(redact=False, require_out=True)
        return opts
    if sub == "output":
        if {"-json", "-raw"} & set(rest):
            raise Denied("output -json/-raw prints sensitive outputs in clear")
        return opts
    if sub == "state":
        if rest and rest[0] in ("list", "show"):
            return opts
        raise Denied("only `state list` and `state show` are allowed (no pull/push/rm/mv/replace-provider)")
    if sub == "workspace":
        if rest and rest[0] in ("list", "show", "select"):
            return opts
        raise Denied("only `workspace list|show|select` are allowed")
    raise Denied(f"terraform {sub!r} is not allowed (apply, destroy, import, refresh, taint, "
                 "force-unlock, console and friends can change infra or state)")


# --------------------------------------------------------------------------- aws
AWS_VALUE_FLAGS = {"--region", "--profile", "--output", "--query", "--endpoint-url", "--ca-bundle",
                   "--cli-read-timeout", "--cli-connect-timeout", "--color", "--cli-binary-format"}
AWS_READ_PREFIX = re.compile(r"^(describe|list|get|lookup|batch-get|search|head)-")
AWS_DENY_OPS = {
    "get-secret-value", "batch-get-secret-value", "get-parameter", "get-parameters",
    "get-parameters-by-path", "get-parameter-history", "get-password-data", "get-login-password",
    "get-authorization-token", "get-session-token", "get-federation-token", "get-object",
    "get-object-torrent", "get-records", "get-shard-iterator", "get-item", "batch-get-item",
    "get-log-events", "get-query-results", "get-function", "get-cluster-credentials",
    "get-credentials-for-identity", "get-open-id-token", "get-open-id-token-for-developer-identity",
    "get-download-url-for-layer", "get-instance-access-details", "get-rest-api-key",
    "get-console-output", "get-console-screenshot", "get-layer-version-by-arn",
}
AWS_DENY_FLAGS = {"--debug", "--include-value", "--include-values", "--with-decryption"}
AWS_STS_OK = {"get-caller-identity", "decode-authorization-message", "get-access-key-info"}


def check_aws(argv):
    args = argv[1:]
    if args and args[0] in ("--version", "help"):
        return {"redact": True}
    bad = AWS_DENY_FLAGS & {a.split("=")[0] for a in args}
    if bad:
        raise Denied(f"flag(s) {sorted(bad)} can leak credentials or secret values")
    pos, i = [], 0
    while i < len(args) and len(pos) < 2:
        a = args[i]
        if a.startswith("-"):
            if a in AWS_VALUE_FLAGS and "=" not in a:
                i += 1
        else:
            pos.append(a)
        i += 1
    if len(pos) < 2:
        raise Denied("could not find `aws <service> <operation>`")
    service, op = pos
    if op == "help":
        return {"redact": True}
    if service == "configure":
        if op in ("list", "list-profiles"):
            return {"redact": True}
        raise Denied("only `aws configure list|list-profiles` is allowed")
    if service == "s3":
        if op == "ls":
            return {"redact": True}
        raise Denied("high-level `aws s3` allows only `ls`; use `aws s3api get-bucket-*` for config")
    if service == "sts":
        if op in AWS_STS_OK:
            return {"redact": True}
        raise Denied(f"sts {op} can mint credentials; only {sorted(AWS_STS_OK)} are allowed")
    if op in AWS_DENY_OPS:
        raise Denied(f"{service} {op} returns secret material or data-plane content")
    if not AWS_READ_PREFIX.match(op):
        raise Denied(f"{service} {op} is not a describe-/list-/get-/lookup-/search-/head- operation")
    return {"redact": True}


# --------------------------------------------------------------------------- azure
AZ_OK_VERBS = {"show", "list", "exists", "query", "version"}
AZ_DENY_WORDS = {
    "list-keys", "list-key", "list-credentials", "list-connection-strings", "list-sas",
    "list-account-sas", "list-service-sas", "list-publishing-credentials",
    "list-publishing-profiles", "get-access-token", "show-connection-string", "generate-sas",
    "get-credentials", "regenerate-key", "regenerate-keys",
}
AZ_DENY_SEQS = [
    ("keyvault", "secret", "show"), ("keyvault", "secret", "download"),
    ("keyvault", "secret", "show-deleted"), ("keys", "list"), ("credential", "show"),
    ("appsettings", "list"), ("connection-string", "list"), ("acr", "login"),
]


def check_az(argv):
    args = argv[1:]
    if "--debug" in args:
        raise Denied("--debug prints request headers and tokens")
    words = leading_words(args)
    if not words:
        if args and args[0] in ("--version", "-h", "--help"):
            return {"redact": True}
        raise Denied("could not find the az command path")
    if words == ["rest"]:
        methods = [m.lower() for m in flag_values(args, "--method", "-m")]
        if any(m != "get" for m in methods):
            raise Denied("az rest is allowed only with --method get")
        urls = flag_values(args, "--url", "-u")
        if any(re.search(r"/list(keys|secrets|credentials|connectionstrings|accountsas|servicesas)", u.lower())
               for u in urls):
            raise Denied("this ARM URL returns keys/secrets")
        return {"redact": True}
    hit = AZ_DENY_WORDS & set(words)
    if hit:
        raise Denied(f"{sorted(hit)} returns keys, tokens, or credentials")
    for seq in AZ_DENY_SEQS:
        if has_seq(words, seq):
            raise Denied(f"`az {' '.join(seq)}` returns secret values")
    verb = words[-1]
    if verb in AZ_OK_VERBS or verb.startswith("list-"):
        return {"redact": True}
    raise Denied(f"az verb {verb!r} is not show/list/exists/query")


# --------------------------------------------------------------------------- gcloud
GCP_OK_VERBS = {"describe", "list", "get-iam-policy", "get-value", "search-all-resources",
                "search-all-iam-policies", "get-ancestors", "get-ancestors-iam-policy",
                "get-effective-iam-policy", "list-grantable-roles"}
GCP_MUTATING = {
    "create", "delete", "update", "patch", "set", "unset", "add-iam-policy-binding",
    "remove-iam-policy-binding", "start", "stop", "suspend", "resume", "reset", "resize",
    "deploy", "import", "export", "ssh", "scp", "enable", "disable", "apply", "replace",
    "undelete", "move", "login", "revoke", "activate", "deactivate", "rotate", "restart",
    "rollback", "cancel", "submit", "execute", "invoke", "call", "sign-blob", "sign-jwt",
    "decrypt", "encrypt", "access", "cp", "mv", "rm", "rsync", "cat", "print-access-token",
    "print-identity-token", "get-credentials", "get-serial-port-output",
}
GCP_MUTATING_PREFIX = ("set-", "add-", "remove-", "update-", "delete-", "create-", "enable-", "disable-")
GCP_DENY_SEQS = [("secrets", "versions", "access"), ("auth", "application-default"),
                 ("services", "api-keys", "get-key-string")]
GCP_DENY_FLAGS = ("--log-http", "--impersonate-service-account", "--access-token-file")


def check_gcloud(argv):
    args = argv[1:]
    if any(a.split("=")[0] in GCP_DENY_FLAGS for a in args):
        raise Denied(f"one of {GCP_DENY_FLAGS} is not allowed (leaks traffic or changes identity)")
    if any(a == "--verbosity=debug" for a in args) or ("--verbosity" in args and "debug" in args):
        raise Denied("--verbosity=debug can leak tokens")
    words = leading_words(args)
    if not words:
        if args and args[0] in ("--version", "-h", "--help"):
            return {"redact": True}
        raise Denied("could not find the gcloud command path")
    if words in (["version"], ["info"]):
        return {"redact": True}
    for seq in GCP_DENY_SEQS:
        if has_seq(words, seq):
            raise Denied(f"`gcloud {' '.join(seq)}` returns secret values or credentials")
    bad = [w for w in words if w in GCP_MUTATING or w.startswith(GCP_MUTATING_PREFIX)]
    if bad:
        raise Denied(f"command path contains mutating/secret verb(s) {bad}")
    if has_seq(words, ("logging", "read")):
        return {"redact": True}
    if any(w in GCP_OK_VERBS for w in words[1:]):
        return {"redact": True}
    raise Denied("gcloud command path has no describe/list/get-iam-policy/get-value verb")


# --------------------------------------------------------------------------- okta (built-in GET client)
OKTA_PATH_OK = re.compile(
    r"^/api/v1/(apps|groups|policies|authorizationServers|trustedOrigins|zones|eventHooks|inlineHooks|"
    r"idps|domains|brands|templates|behaviors|meta|mappings|org|logs|users|iam|authenticators|"
    r"threats|devices|roles|features|profileMappings|email-servers|captchas|risk|"
    r"push-providers|hook-keys|api-tokens)(/|\?|$)"
)
OKTA_PATH_DENY = re.compile(r"(/sessions|/factors|/lifecycle|/credentials/(csrs|change_password)|\.\.)")


def okta_get(path, max_pages):
    base = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
    token = os.environ.get("OKTA_API_TOKEN", "")
    bearer = os.environ.get("OKTA_ACCESS_TOKEN", "")
    if not base or not (token or bearer):
        raise Denied("set OKTA_ORG_URL and OKTA_API_TOKEN (or OKTA_ACCESS_TOKEN) in the environment; "
                     "the token is read from env and never printed")
    if not path.startswith("/") or not OKTA_PATH_OK.match(path) or OKTA_PATH_DENY.search(path):
        raise Denied("Okta path must be a GET under an allowlisted /api/v1/<resource> prefix "
                     "(extend OKTA_PATH_OK in ro_guard.py if you need more)")
    host = urllib.parse.urlparse(base).netloc
    auth = f"SSWS {token}" if token else f"Bearer {bearer}"
    url, pages, results, single = base + path, 0, [], None
    while url and pages < max_pages:
        if urllib.parse.urlparse(url).netloc != host:
            raise Denied("pagination link points to a different host; refusing to send credentials there")
        req = urllib.request.Request(url, headers={"Authorization": auth, "Accept": "application/json"},
                                     method="GET")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body, link = json.loads(resp.read().decode() or "null"), resp.headers.get_all("Link") or []
                break
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 2:
                    time.sleep(2 ** attempt * 2)
                    continue
                raise Denied(f"Okta returned HTTP {e.code} for GET {url.replace(base, '')}")
        pages += 1
        if isinstance(body, list):
            results.extend(body)
        else:
            single = body
        url = None
        for h in link:
            m = re.search(r'<([^>]+)>;\s*rel="next"', h)
            if m:
                url = m.group(1)
    return results if single is None else single


# --------------------------------------------------------------------------- dispatch
CHECKERS = {"terraform": check_terraform, "tofu": check_terraform, "aws": check_aws,
            "az": check_az, "gcloud": check_gcloud}


def emit(text, out_path):
    if out_path:
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        print(f"ro_guard: wrote {len(text)} bytes to {out_path}")
        return
    if len(text) > MAX_STDOUT_CHARS:
        sys.stdout.write(text[:MAX_STDOUT_CHARS])
        print(f"\nro_guard: output truncated at {MAX_STDOUT_CHARS} chars; re-run with --out FILE "
              "and project fields with jq", file=sys.stderr)
    else:
        sys.stdout.write(text)


def parse_leading(argv):
    """Consume only guard options at the very front; everything after is the command verbatim."""
    out, check, i = None, False, 0
    while i < len(argv):
        a = argv[i]
        if a == "--out" and i + 1 < len(argv):
            out, i = argv[i + 1], i + 2
        elif a.startswith("--out="):
            out, i = a.split("=", 1)[1], i + 1
        elif a == "--check":
            check, i = True, i + 1
        elif a == "--":
            i += 1
            break
        else:
            break
    return out, check, argv[i:]


def main():
    out_path, check_only, rest = parse_leading(sys.argv[1:])
    ns = argparse.Namespace(out=out_path, check=check_only)
    if not rest:
        print(__doc__)
        return 2
    try:
        if rest[0] == "okta":
            m = argparse.ArgumentParser(prog="ro_guard.py okta")
            m.add_argument("method")
            m.add_argument("path")
            m.add_argument("--max-pages", type=int, default=20)
            oa = m.parse_args(rest[1:])
            if oa.method.upper() != "GET":
                raise Denied("Okta access is GET-only")
            if ns.check:
                print("ro_guard: OK")
                return 0
            data = redact(okta_get(oa.path, oa.max_pages))
            emit(json.dumps(data, indent=2), ns.out)
            return 0

        tool = os.path.basename(rest[0])
        if tool not in CHECKERS:
            raise Denied(f"{tool!r} is not a supported tool (terraform, tofu, aws, az, gcloud, okta). "
                         "Ask the user before adding a provider, then extend this script.")
        opts = CHECKERS[tool](rest)
        if opts.get("require_out") and not ns.out:
            raise Denied("this command prints unmasked values; re-run with --out FILE and read it via "
                         "drift_report.py")
        if ns.check:
            print("ro_guard: OK")
            return 0
        try:
            proc = subprocess.run(rest, capture_output=True, text=True)
        except FileNotFoundError:
            print(f"ro_guard: {rest[0]!r} is not installed or not on PATH", file=sys.stderr)
            return 127
        stdout = proc.stdout
        if opts.get("redact", True):
            try:
                stdout = json.dumps(redact(json.loads(stdout)), indent=2)
            except (json.JSONDecodeError, ValueError):
                pass  # non-JSON output is passed through unchanged
        emit(stdout, ns.out)
        sys.stderr.write(proc.stderr)
        return proc.returncode
    except Denied as e:
        print(f"ro_guard: DENIED - {e}", file=sys.stderr)
        return DENIED


if __name__ == "__main__":
    sys.exit(main())
