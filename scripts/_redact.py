"""Shared secret-redaction helpers for the drift-reconcile scripts.

Key-based and deliberately conservative: only *string* values under keys that
look like secrets are masked, so numeric/boolean config such as
`accessTokenLifetimeMinutes` or `tokenType` stays intact for drift analysis.
"""
import re

REDACTED = "<redacted>"

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_SECRET_KEY = re.compile(
    r"^(?:.*_)?(?:"
    r"password|passwd|passphrase|pass|pwd|secret|client_secret|secret_access_key|"
    r"secret_string|secret_binary|api_key|apikey|private_key|private_key_pem|"
    r"token|access_token|refresh_token|id_token|auth_token|session_token|"
    r"security_token|bearer_token|sas_token|ssws_token|connection_string|"
    r"shared_access_key|primary_key|secondary_key|account_key|master_key|"
    r"user_data|user_data_base64|custom_data|startup_script|metadata_startup_script"
    r")$"
)
# Pagination tokens look secret-ish but are not.
_NOT_SECRET = {"next_token", "page_token", "next_page_token", "continuation_token", "next_marker"}

_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def norm_key(key) -> str:
    k = _CAMEL.sub("_", str(key))
    return re.sub(r"[-.\s]+", "_", k).lower()


def is_secret_key(key) -> bool:
    k = norm_key(key)
    return k not in _NOT_SECRET and bool(_SECRET_KEY.match(k))


def looks_secret_value(v) -> bool:
    return isinstance(v, str) and bool(_PEM.search(v))


def redact(obj):
    """Return a deep copy of parsed JSON with secret-looking string values masked."""
    if isinstance(obj, dict):
        # {"name": "DB_PASSWORD", "value": "hunter2"} pairs (ECS, App Service, Cloud Run env)
        name_val = next((obj[k] for k in obj if str(k).lower() in ("name", "key")), None)
        pair_secret = isinstance(name_val, str) and is_secret_key(name_val)
        out = {}
        for k, v in obj.items():
            if isinstance(v, str) and v != "" and (
                is_secret_key(k) or (pair_secret and str(k).lower() == "value") or looks_secret_value(v)
            ):
                out[k] = REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if looks_secret_value(obj):
        return REDACTED
    return obj
