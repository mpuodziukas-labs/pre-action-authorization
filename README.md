# pre-action-authorization

Proves: a planted tool call that is not on the allowlist fails closed, and the shell class is an allowlist of commands, not a denylist of verbs. Verify in 60s: python3 evaluate.py

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
| secret-glob | 6/6 |
| env-or-tilde | 4/4 |
| destructive | 6/6 |
| shell-expansion | 3/3 |
| interpreter | 2/2 |
| network-tool | 1/1 |
| git-force | 3/3 |
| path-arg | 1/1 |
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
- shell-expansion, interpreter, network-tool, git-force, path-arg: s-glob, s-brace, s-ansic, s-bash-c, s-python-c, s-curl-upload, s-git-C-force, s-git-plus-ref, s-git-clean, s-cat-outside. The shell class is an allowlist: argv[0] must be an exact bare name from a committed list, globs, braces, dollar quoting and escapes are refused, interpreters and network tools are refused, git is limited to read-style subcommands with listed flags, and every argument passes the path and host rules.
- chaining: s-chain, s-pipe, s-subst. Chaining, pipes and substitution characters are DENY.
- malformed, fail-closed: p-nul, s-unbalanced, x-unknown-class, x-empty, x-whitespace. A NUL byte, an unparseable command, an unknown class and an empty value are DENY. The tests also send malformed requests and malformed policies and require DENY.

The tests also break the gate on purpose (symlinks not resolved, user-info allowed, empty verb list, empty secret list, non-ASCII hosts allowed, model compare made case-insensitive) and require the table to change each time. Each of three single-line guards in gate.py (raw path segments in the secret check, the percent check, the URL backslash check) has a direct test, so deleting any one fails a test.

## Honesty

This is a small deterministic gate, not a product, and it is a policy check, not a sandbox: it decides, it does not contain anything. The cases in cases.jsonl are synthetic and written for this repo, run against a throwaway workspace the runner builds in a temp directory. I did not test it against a real agent, real traffic or a real shell, and I did not measure how often it refuses a legitimate call outside the ten controls.

## Limitations

- Hosts are compared by name only. DNS rebinding and redirects after the check are out of scope.
- Paths are checked at decision time, so a file swapped for a symlink afterwards is not seen.
- A literal file name containing a percent sign or dollar sign is denied.
- Shell parsing is conservative: any metacharacter, glob or expansion is DENY, so pipelines and wildcards are refused, and only ten command names are allowed.
- Values over 4096 characters are DENY with reason oversize.
- Hard-linked regular files (more than one link) are DENY inside the workspace, which also refuses a legitimately hard-linked file.

## Hostile review 2026-10-04

An adversarial review (RED-RUN-REVIEW.txt) found 5 kill, 6 high, 6 medium, 7 pass rows. Fixed: 5 kill, 6 high, 5 medium (M1 stays disclosed). The tests are in tests/test_hostile.py and call the gate only.

- K1-K5: shell check is now an allowlist of exact command names with metacharacter, glob, brace, dollar and escape refusal; interpreters and network tools refused; every argument runs the path and host rules.
- H1: path-like shell arguments go through the path rule.
- H2: git is limited to read-style subcommands with listed flags; push, clean, reset and global options are refused.
- H3: interpreters with code flags are refused by the allowlist.
- H4: secret names widened (id_*, *.p12, *.pfx, credentials*, .git, .netrc, .npmrc, .pypirc, .kube, .docker).
- H5: regular files with more than one link are DENY.
- H6: headline now matches the mechanism.
- M2: a workspace of /, a system directory, home or an ancestor of home is refused.
- M3: values over 4096 characters are DENY (oversize), 1 MB returns in under a second.
- M4: only exact str and dict types are accepted.
- M5: evaluate.py exits 1 when any case fails.
- M6: each of the three guards has a direct test, and the case-insensitive mutant now mutates gate.py.
- M1: unchanged, disclosed above (decision time check, not bound to the act).
- Changed expectation: test_mutant_destructive_verbs_empty now pins the refusal reason, because the allowlist denies rm with or without the verb list.

## CI

The workflow in .github/workflows/ci.yml runs `python evaluate.py` and `python -m pytest -q` on push and pull request, with each action pinned to a commit.

## License

MIT, see LICENSE.
