"""Deterministic pre-action authorization for agent tool calls.

authorize(request, policy) -> ("ALLOW" | "DENY", reason)

request: {"class": "model" | "egress" | "path" | "shell", "value": str}
Anything not recognized, malformed or ambiguous is DENY.
"""
import fnmatch
import os
import re
import shlex
from urllib.parse import urlsplit

SECRET_GLOBS = (".env*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", ".ssh", ".aws", ".gnupg", ".netrc")
DESTRUCTIVE = frozenset({
    "rm", "rmdir", "unlink", "dd", "mkfs", "shred", "truncate", "chmod", "chown", "kill", "killall",
    "pkill", "shutdown", "reboot", "sudo", "su", "mv",
})
SHELL_META = re.compile(r"[;&|`<>\n\r]|\$\(|\$\{")
DESTRUCTIVE_PAIRS = (("git", "push", "--force"), ("git", "push", "-f"), ("git", "reset", "--hard"),
                     ("git", "clean", "-f"))
DESTRUCTIVE_FLAGS = frozenset({"-delete", "--delete"})

_resolve = os.path.realpath


def _ascii(s):
    return s.isascii()


def _bad_netloc(netloc):
    return "@" in netloc


def _deny(reason):
    return "DENY", reason


def _model(value, policy):
    models = policy.get("models")
    if not isinstance(models, (list, tuple)):
        return _deny("no model allowlist in policy")
    if value in models:
        return "ALLOW", "model is on the allowlist"
    return _deny("model id is not an exact allowlist entry")


def _egress(value, policy):
    hosts = policy.get("hosts")
    if not isinstance(hosts, (list, tuple)):
        return _deny("no host allowlist in policy")
    if not _ascii(value) or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        return _deny("url has non-ASCII, whitespace, control or backslash characters")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return _deny("url does not parse")
    if parts.scheme != "https":
        return _deny("scheme is not https")
    if _bad_netloc(parts.netloc):
        return _deny("user-info in url")
    if port not in (None, 443):
        return _deny("non-default port")
    host = parts.hostname or ""
    if host in [h.lower() for h in hosts]:
        return "ALLOW", "host is on the allowlist"
    return _deny("host is not an exact allowlist entry")


def _path(value, policy):
    ws = policy.get("workspace")
    if not isinstance(ws, str) or not os.path.isabs(ws) or not os.path.isdir(ws):
        return _deny("policy workspace is not an existing absolute directory")
    if "\x00" in value or any(ord(c) < 32 for c in value):
        return _deny("control character in path")
    if value.startswith("~") or "$" in value or "%" in value:
        return _deny("tilde or environment variable in path")
    root = _resolve(ws)
    full = _resolve(value if os.path.isabs(value) else os.path.join(root, value))
    if os.path.commonpath([root, full]) != root:
        return _deny("path resolves outside the workspace")
    names = [p.lower() for p in os.path.relpath(full, root).split(os.sep)]
    names += [p.lower() for p in value.split("/")]
    for name in names:
        for glob in SECRET_GLOBS:
            if fnmatch.fnmatchcase(name, glob):
                return _deny(f"path matches secret glob {glob}")
    return "ALLOW", "path is inside the workspace and not secret"


def _shell(value, policy):
    if SHELL_META.search(value):
        return _deny("shell metacharacter (chaining, pipe, substitution or redirect)")
    try:
        tokens = shlex.split(value)
    except ValueError:
        return _deny("command does not parse")
    if not tokens:
        return _deny("empty command")
    low = [t.lower() for t in tokens]
    for t in low:
        if os.path.basename(t) in DESTRUCTIVE:
            return _deny(f"destructive verb {os.path.basename(t)}")
    names = [os.path.basename(low[0])] + low[1:]
    for pair in DESTRUCTIVE_PAIRS:
        if tuple(names[:2]) == pair[:2] and pair[2] in names[2:]:
            return _deny("destructive git operation")
    if DESTRUCTIVE_FLAGS & set(low):
        return _deny("destructive flag")
    return "ALLOW", "command has no destructive verb"


HANDLERS = {"model": _model, "egress": _egress, "path": _path, "shell": _shell}


def authorize(request, policy):
    if not isinstance(request, dict) or set(request) != {"class", "value"}:
        return _deny("request must be exactly {class, value}")
    cls, value = request["class"], request["value"]
    if not isinstance(cls, str) or not isinstance(value, str) or not value.strip():
        return _deny("class and value must be non-empty strings")
    if not isinstance(policy, dict):
        return _deny("policy is not a mapping")
    handler = HANDLERS.get(cls)
    if handler is None:
        return _deny(f"unknown class '{cls}'")
    try:
        return handler(value, policy)
    except Exception as exc:  # fail closed on any unexpected error
        return _deny(f"internal error: {type(exc).__name__}")
