# pre-action-authorization

An autonomous agent can call a tool with a model, host, file or shell command nobody approved. This gate sits in front of each tool call and returns ALLOW or DENY with a reason from a fixed allowlist, and fails closed on anything it does not recognize.

## Run it in 60 seconds

```
python3 -m pip install pytest
python3 evaluate.py
python3 -m pytest -q
```

## Results

| bad caught | good passed |
|---|---|
| 1/1 | 1/1 |

## Honesty Statement

Synthetic data. Not production, not client data.

## Limitations

Small synthetic corpus. Replace before drawing conclusions.
