# pre-action-authorization

Proves: a planted tool call outside the allowlist fails closed. Verify in 60s: python3 evaluate.py

An autonomous agent can call a tool with a model, host, file or shell command that nobody approved, and the damage is done before anyone reads a log. The team that owns the data and the bill pays for it, through leaked files, traffic to an unknown host or a deleted directory.

## Run it (60s)

```
python3 -m pip install pytest
python3 evaluate.py
python3 -m pytest -q
```

`python3 evaluate.py` printed:

```
| bypass class | denied as expected |
|---|---|
| unknown-tier | 2/2 |
| case-variant | 4/4 |
| unknown-host | 1/1 |
| host-trick | 7/7 |
| userinfo | 3/3 |
| port | 1/1 |
| scheme | 1/1 |
| homoglyph | 2/2 |
| outside-workspace | 1/1 |
| traversal | 3/3 |
| symlink | 2/2 |
| secret-glob | 4/4 |
| env-or-tilde | 4/4 |
| destructive | 6/6 |
| chaining | 3/3 |
| malformed | 2/2 |
| fail-closed | 3/3 |
| control (allowed) | 10/10 |
```

`python3 -m pytest -q` prints a passed count with no failures.

## What each planted RED case proves

A request is exactly `{"class": ..., "value": ...}` and the policy holds the allowlists. The gate returns ALLOW or DENY with a reason. Each row of the table is one bypass family, and every planted case in cases.jsonl must get the verdict it is labeled with. The ten controls (c-model, c-egress, c-egress-slash, c-egress-dslash, c-egress-case, c-egress-kb, c-path, c-path-rel, c-shell, c-shell-git) must stay ALLOW.

- unknown-tier, case-variant: m-unknown, m-prefix, m-case, m-space, p-env-case, s-rm-case. A model id must match an allowlist entry exactly. Different case, a trailing space or a longer id is DENY, and so is a secret file or destructive verb in different case.
- unknown-host, host-trick: e-unknown, e-suffix, e-prefix, e-trailing-dot, e-backslash, e-scheme-relative, e-path-host, e-whitespace. A host is allowed only when it equals an allowlisted name. Look-alike suffixes, prefixes, a trailing dot, backslashes, scheme-relative URLs and embedded whitespace are DENY.
- userinfo, port, scheme: e-userinfo, e-userinfo-port, e-userinfo-legit-host, e-port, e-http. Credentials in the URL, a non-default port or plain http is DENY, even when the host name is on the list.
- homoglyph: e-homoglyph, e-kelvin. A host with non-ASCII look-alike characters is DENY.
- outside-workspace, traversal, symlink: p-outside, p-traversal, p-traversal-rel, p-traversal-deep, p-symlink, p-symlink-secret. A path must resolve, symlinks included, inside the workspace. Dot-dot escapes and links that point out are DENY.
- secret-glob: p-env, p-env-variant, p-key-dir, p-pem. Environment files, keys and .ssh paths are DENY inside the workspace too.
- env-or-tilde: p-envvar, p-envvar-braced, p-tilde, p-tilde-user. Unexpanded variables and tilde paths are DENY.
- destructive: s-rm, s-rm-path, s-dd, s-sudo, s-force, s-find-delete. Destructive verbs, forced git operations and delete flags are DENY.
- chaining: s-chain, s-pipe, s-subst. Chaining, pipes and substitution characters are DENY.
- malformed, fail-closed: p-nul, s-unbalanced, x-unknown-class, x-empty, x-whitespace. A NUL byte, an unparseable command, an unknown class and an empty value are DENY. The tests also send malformed requests and malformed policies and require DENY.

The tests also break the gate on purpose (symlinks not resolved, user-info allowed, empty verb list, empty secret list, non-ASCII hosts allowed, model compare made case-insensitive) and require the table to change each time.

## Honesty

This is a small deterministic gate, not a product, and it is a policy check, not a sandbox: it decides, it does not contain anything. The cases in cases.jsonl are synthetic and written for this repo, run against a throwaway workspace the runner builds in a temp directory. I did not test it against a real agent, real traffic or a real shell, and I did not measure how often it refuses a legitimate call outside the ten controls.

## Limitations

- Hosts are compared by name only. DNS rebinding and redirects after the check are out of scope.
- Paths are checked at decision time, so a file swapped for a symlink afterwards is not seen.
- A literal file name containing a percent sign or dollar sign is denied.
- Shell parsing is conservative: any chaining or redirect character is DENY, so some safe pipelines are refused.
- The destructive verb list is short and fixed. An allowlist of commands would be stricter.

## CI

The workflow in .github/workflows/ci.yml runs `python evaluate.py` and `python -m pytest -q` on push and pull request, with each action pinned to a commit.

## License

MIT, see LICENSE.
