# Demo 01 - Basic ffuf triage

## Scenario

You ran an **authorized** content-discovery scan against a web app you are
permitted to test:

```
ffuf -u https://app.example.com/FUZZ -w wordlist.txt -o ffuf.json -of json
```

ffuf returned dozens of hits. Most are noise -- the app serves an identical
4242-byte soft-404 page for unknown paths, so every miss shows up as a
`200`. DIRSIGHT separates the signal from that noise.

## Run it

```
python -m dirsight analyze demos/01-basic/ffuf.json
# or JSON for tooling / CI:
python -m dirsight analyze demos/01-basic/ffuf.json --format json
```

## What to expect

- The repeated `4242`-byte `200`s (`/about`, `/contact`, `/help`, `/news`)
  are flagged `[noise]` (wildcard / soft-404) and pushed to the bottom.
- High-interest endpoints float to the top with reasons:
  - `/.git/config` (exposed VCS metadata)
  - `/.env` (secrets file)
  - `/admin` -> redirects to auth (401/302)
  - `/backup.sql` (database dump)
  - `/api/v1/swagger.json` (API surface)
- Exit code is `2` because high-interest findings are present (useful for
  failing a CI pipeline / alerting), `0` when clean.

## Scope reminder

DIRSIGHT only *reads* output you already collected. It performs no network
requests and grants no attack capability -- it is an analysis/triage aid for
authorized testing.
