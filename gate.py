"""Deterministic pre-action authorization for agent tool calls.

authorize(request, policy) -> ("ALLOW" | "DENY", reason)

request: {"class": "model" | "egress" | "path" | "shell", "value": str}
Anything not recognized, malformed or ambiguous is DENY. The shell class is an allowlist of exact
command names; every argument must also pass the path rule (or the host rule for URLs).
"""
import fnmatch
import os
import re
import shlex
import stat
from urllib.parse import urlsplit

SECRET_GLOBS = (".env*", "*.pem", "*.key", "*.p12", "*.pfx", "id_*", ".ssh", ".aws", ".gnupg", ".netrc", ".npmrc",
                ".pypirc", ".git", ".kube", ".docker", "credentials*")
DESTRUCTIVE = frozenset({
    "rm", "rmdir", "unlink", "dd", "mkfs", "shred", "truncate", "chmod", "chown", "kill", "killall",
    "pkill", "shutdown", "reboot", "sudo", "su", "mv",
})
MAX_LEN = 4096
# Shell policy is an allowlist: argv[0] must be one of these exact bare names.
ALLOWED_COMMANDS = frozenset({"ls", "cat", "head", "tail", "wc", "grep", "echo", "pwd", "find", "git"})
# Named only to give a clear refusal reason; they are refused anyway by not being on the allowlist.
INTERPRETERS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "env", "xargs", "python", "python3", "node", "perl",
                          "ruby", "eval", "exec", "awk", "sed"})
NETWORK_TOOLS = frozenset({"curl", "wget", "scp", "nc", "ncat", "ssh", "sftp", "rsync", "ftp", "telnet"})
# Any metacharacter, glob, expansion, escape, comment, control or non-ASCII character is refused.
SHELL_META = re.compile(r"[;&|`<>$\\?*\[\]{}()!#~\x00-\x08\x0a-\x1f\x7f]|[^\x00-\x7f]")
FLAG = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]*$")
NUMFLAG = re.compile(r"^-[0-9]+$")
FIND_FLAGS = frozenset({"-name", "-iname", "-type", "-maxdepth", "-mindepth", "-print"})
GIT_SAFE = {  # subcommand -> allowed flags; anything else is refused
    "status": {"--short", "-s", "-b", "--branch", "--porcelain", "-sb"},
    "log": {"--oneline", "-n", "--stat", "--graph", "-p", "--name-only", "--no-color"},
    "diff": {"--stat", "--name-only", "--cached", "--staged", "--no-color", "--name-status"},
    "show": {"--stat", "--oneline", "--name-only", "--no-color"},
    "ls-files": {"--cached", "-c", "--others", "-o"},
    "rev-parse": {"--show-toplevel", "--abbrev-ref", "--short"},
    "add": set(),
    "commit": {"-m"},
}
UNSAFE_WORKSPACES = ("/", "/etc", "/usr", "/var", "/bin", "/sbin", "/System", "/Library", "/tmp")

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


def _unsafe_workspace(root):
    home = _resolve(os.path.expanduser("~"))
    if root in {_resolve(p) for p in UNSAFE_WORKSPACES} or root == home:
        return True
    return home.startswith(root.rstrip(os.sep) + os.sep)


def _path(value, policy):
    ws = policy.get("workspace")
    if not isinstance(ws, str) or not os.path.isabs(ws) or not os.path.isdir(ws):
        return _deny("policy workspace is not an existing absolute directory")
    root = _resolve(ws)
    if _unsafe_workspace(root):
        return _deny("policy workspace is a system directory, the home directory or an ancestor of it")
    if "\x00" in value or any(ord(c) < 32 for c in value):
        return _deny("control character in path")
    if value.startswith("~") or "$" in value or "%" in value:
        return _deny("tilde or environment variable in path")
    full = _resolve(value if os.path.isabs(value) else os.path.join(root, value))
    if os.path.commonpath([root, full]) != root:
        return _deny("path resolves outside the workspace")
    names = [p.lower() for p in os.path.relpath(full, root).split(os.sep)]
    names += [p.lower() for p in value.split("/")]
    for name in names:
        for glob in SECRET_GLOBS:
            if fnmatch.fnmatchcase(name, glob):
                return _deny(f"path matches secret glob {glob}")
    try:
        st = os.stat(full)
    except OSError:
        st = None
    if st is not None and stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        return _deny("hard link: regular file has more than one link")
    return "ALLOW", "path is inside the workspace and not secret"


def _shell_arg(arg, policy):
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", arg):
        verdict, reason = _egress(arg, policy)
        return (verdict, "url argument: " + reason) if verdict == "DENY" else None
    verdict, reason = _path(arg, policy)
    return (verdict, "path argument: " + reason) if verdict == "DENY" else None


def _git(args, policy):
    if not args or args[0] not in GIT_SAFE:
        return _deny("git subcommand is not on the allowlist (global options, push, clean, reset refused)")
    sub, rest = args[0], args[1:]
    allowed = GIT_SAFE[sub]
    i = 0
    while i < len(rest):
        a = rest[i]
        if sub == "commit" and a == "-m":
            if i + 1 >= len(rest):
                return _deny("commit -m needs a message")
            i += 2
            continue
        if a.startswith("-"):
            if not (a in allowed or (sub == "log" and NUMFLAG.match(a))):
                return _deny(f"git {sub} flag {a} is not on the allowlist")
        elif a != "--":
            if ":" in a:
                return _deny("git argument contains ':'")
            bad = _shell_arg(a, policy)
            if bad:
                return bad
        i += 1
    return "ALLOW", f"git {sub} is on the allowlist"


def _shell(value, policy):
    if SHELL_META.search(value):
        return _deny("shell metacharacter, glob, expansion, escape or control character")
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        return _deny("command does not parse")
    if not tokens:
        return _deny("empty command")
    cmd, args = tokens[0], tokens[1:]
    if "" in tokens:
        return _deny("empty argument")
    base = os.path.basename(cmd.lower())
    if base in DESTRUCTIVE:
        return _deny(f"destructive verb {base}")
    if base in NETWORK_TOOLS:
        return _deny(f"network tool {base} is refused")
    if base in INTERPRETERS:
        return _deny(f"interpreter {base} is refused")
    if cmd not in ALLOWED_COMMANDS:
        return _deny("command is not an exact allowlist entry")
    ok, why = _path(".", policy)
    if ok == "DENY":
        return _deny(why)
    if cmd == "git":
        return _git(args, policy)
    for a in args:
        if cmd == "find" and a.startswith("-"):
            if a not in FIND_FLAGS:
                return _deny(f"find flag {a} is not on the allowlist")
        elif a.startswith("-"):
            if not (FLAG.match(a) or NUMFLAG.match(a)):
                return _deny("flag form is not allowed")
        else:
            bad = _shell_arg(a, policy)
            if bad:
                return bad
    return "ALLOW", "command is on the allowlist and every argument passed the path and host rules"


HANDLERS = {"model": _model, "egress": _egress, "path": _path, "shell": _shell}


def authorize(request, policy):
    if type(request) is not dict or set(request) != {"class", "value"}:
        return _deny("request must be exactly {class, value}")
    cls, value = request["class"], request["value"]
    if type(cls) is not str or type(value) is not str or not value.strip():
        return _deny("class and value must be non-empty strings")
    if len(value) > MAX_LEN:
        return _deny(f"oversize value (limit {MAX_LEN} characters)")
    if not isinstance(policy, dict):
        return _deny("policy is not a mapping")
    handler = HANDLERS.get(cls)
    if handler is None:
        return _deny(f"unknown class '{cls}'")
    try:
        return handler(value, policy)
    except Exception as exc:  # fail closed on any unexpected error
        return _deny(f"internal error: {type(exc).__name__}")
