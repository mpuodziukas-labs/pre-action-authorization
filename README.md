# pre-action-authorization

Proves: pre-action authorization for agent tool calls. Verify in 60s: `python3 evaluate.py && python3 -m pytest -q`.

![CI](https://github.com/mpuodziukas-labs/pre-action-authorization/actions/workflows/ci.yml/badge.svg)

## Business problem

An autonomous agent can call a tool with a model, host, file or shell command
nobody approved. This gate sits in front of each tool call and returns ALLOW or
DENY with a reason from a fixed allowlist. It is deterministic, has no model in
the loop, and fails closed: an unknown class, a malformed request or any
internal error is DENY.

## Run it in 60 seconds

```
python3 -m pip install pytest
python3 evaluate.py
python3 -m pytest -q
```

## What it decides

A request is exactly `{"class": ..., "value": ...}` and the policy holds the allowlists.

| class | ALLOW only when |
|---|---|
| model | the id is an exact entry in the model allowlist |
| egress | https, no user-info, default port, ASCII host equal to an allowlisted host |
| path | it resolves (symlinks included) inside the declared workspace and matches no secret glob |
| shell | it parses, has no chaining or substitution characters and no destructive verb |

## Results

Each row is one bypass family. Every planted case in cases.jsonl must get the
verdict it is labeled with.

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

## Honesty Statement

The cases in cases.jsonl are synthetic and written for this repo, against a
throwaway workspace the runner builds in a temp directory. The gate is a policy
check, not a sandbox: it decides, it does not contain anything.

## Limitations

- Hosts are compared by name only. DNS rebinding and redirects after the check are out of scope.
- Paths are checked at decision time, so a file swapped for a symlink afterwards is not seen.
- A literal file name containing a percent sign or dollar sign is denied.
- Shell parsing is conservative: any chaining or redirect character is DENY, so some safe pipelines are refused.
- The destructive verb list is short and fixed. An allowlist of commands would be stricter.
