# mystrio

A masking reverse-proxy that sits between Grafana and your log/observability
backends. Grafana talks to **mystrio**, never directly to Loki or
Elasticsearch — mystrio forwards the request, and on the way back masks
sensitive fields (IIN/BIN, names, phones, e-mails, tokens, card/account
numbers, IPs, etc.) in the response before Grafana ever sees it.

```
Grafana ──HTTP(S)──▶ mystrio ──HTTP(S)──▶ Loki / Elasticsearch (upstream)
                         │
                         └── masks sensitive fields in the response
```

- **Loki** (`/loki/*`): every response is scanned line-by-line; JSON log
  lines are masked by key name (recursively, including JSON escaped inside
  a string field), and regex rules catch non-JSON formats (SQL, logfmt,
  bare values in a URL).
- **Elasticsearch** (`/elastic/*`): only `_search`/`_msearch` responses are
  masked, structurally, by walking each hit's `_source` and masking
  matching JSON keys. Other endpoints (`_mapping`, `_field_caps`, index
  listings) pass through untouched.
- Both backends are optional and independently toggled — run with just
  Loki, just Elasticsearch, or both.
- Auth headers (`Authorization`, Basic Auth) are passed through unchanged;
  mystrio does not store or substitute credentials.
- mystrio's own logs contain only request metadata (path, status,
  content-type) — never log content or secrets.
- An optional `/test-me` page lets you paste a candidate `rules.yaml` and a
  log line and preview the masked result, without touching the live rules.

## Run

```bash
export LOKI_ENABLED=true
export LOKI_URL=http://loki-dev.example
export RULES_PATH=./configs/rules.yaml
export PORT=:8080

go run .
```

Or:

```bash
go build -o bin/mystrio .
./bin/mystrio
```

At least one of `LOKI_ENABLED`/`ELASTIC_ENABLED` must be `true`, or the
process exits at startup with an error — this includes the docker-compose
stack below, whose defaults leave both `false`.

## Env

| Variable | Default | Description |
| --- | --- | --- |
| `LOKI_ENABLED` | `false` | Enable the `/loki` proxy route |
| `LOKI_URL` | — | Upstream Loki base URL; required if `LOKI_ENABLED=true` |
| `ELASTIC_ENABLED` | `false` | Enable the `/elastic` proxy route |
| `ELASTIC_URL` | — | Upstream Elasticsearch base URL; required if `ELASTIC_ENABLED=true` |
| `PORT` | `:8080` | Listen address |
| `MAX_RESPONSE_BYTES` | `33554432` | Skip masking above this size (shared by both backends) |
| `TEST_ME_ENABLED` | `false` | Enable the `/test-me` masking-preview UI |
| `BASE_PATH` | `` (root) | Path prefix for `/test-me` only (e.g. `/mystrio`); does not affect `/loki`, `/elastic`, `/healthz` |
| `RULES_PATH` | — | Path to the masking rules YAML file; required, loaded once at startup |

Masking rules are loaded from the file at `RULES_PATH` **once, at process
startup** — there is no hot-reload. To change rules, edit the file and
restart the process (or `docker compose restart mystrio` — no image rebuild
needed if the file is bind-mounted, see below). The same rules apply to both
Loki and Elasticsearch: `json_keys` rules mask matching keys recursively in
both; the `regex` rules apply only to Loki log lines (Elasticsearch
`_source` fields are masked structurally by JSON key, not by regex over raw
text).

## Routing

- `/loki/*` → forwarded to `LOKI_URL` (prefix stripped)
- `/elastic/*` → forwarded to `ELASTIC_URL` (prefix stripped); response
  masking is applied only to `_search`/`_msearch` responses — other
  Elasticsearch endpoints (`_mapping`, `_field_caps`, index listings) pass
  through unmodified.
- `/healthz` → `ok`

## Masking test UI

Set `TEST_ME_ENABLED=true` to expose `/test-me` (or `{BASE_PATH}/test-me` if
`BASE_PATH` is set): a page to paste a candidate `rules.yaml` and a log line,
and preview the masked result. The rules editor is prefilled with the
service's actual embedded rules, but **edits there are never applied to the
running service** — each preview parses the submitted rules fresh and
discards them. Off by default; not intended to be exposed outside a
trusted network (mystrio has no built-in auth).

The YAML editor uses [CodeMirror 5](https://codemirror.net/5/) (MIT
licensed), vendored under `internal/testme/vendor/` and served by mystrio
itself via `go:embed` — no CDN, no network calls from the browser other than
back to mystrio.

## Local Grafana (docker compose)

Grafana and mystrio run in one compose network. Loki datasource URL is
`http://mystrio:8080/loki` — **not** `localhost` / `0.0.0.0` (those point
inside the Grafana container).

```bash
export LOKI_ENABLED=true
export LOKI_URL=https://loki-prod.example
./run.sh
# or: docker compose up -d --build
```

- Grafana: http://localhost:3000 (admin/admin)
- Proxy on host: http://localhost:9999/healthz
- Masking test UI (on by default in compose): http://localhost:9999/test-me
- Request logs: `docker compose logs -f mystrio`
- Rules: bind-mounted from `configs/rules.yaml` — edit that file and run
  `docker compose restart mystrio` to apply, no rebuild needed.

Open dashboard **Mystrio Logs**.

To also proxy Elasticsearch, set `ELASTIC_ENABLED=true` and `ELASTIC_URL=...`
before running `./run.sh` (see `docker-compose.yml`), then add a Grafana
Elasticsearch datasource pointed at `http://mystrio:8080/elastic`.

Variables (examples):
- `namespace` (`k8s_namespace`) — custom: `bank`, `digital`, `infra`, `actions`
- `k8s_app` — `label_values({k8s_namespace_name=~"$namespace"}, k8s_app)`
- `find` — textbox for line filter `|= "$find"` (empty = all lines)

Panel LogQL:

```logql
{k8s_cluster="kuber-prod", k8s_namespace_name="$namespace", k8s_app="$k8s_app"} |= "$find"
```

If Loki requires Basic Auth, add it in Grafana → Data sources → Loki (passed through).

### Run proxy on host only (optional)

```bash
PORT=0.0.0.0:9999 LOKI_ENABLED=true LOKI_URL=... go run .
```

Then set Grafana datasource to `http://host.docker.internal:9999/loki` (not `localhost`).

## Rules

- **JSON logs (Loki):** mask by key name (recursive), e.g. `iin` / `biin`;
  and regex over the (re)serialized line for format-based or non-JSON
  matches (e-mail, phone, JWT, SQL/logfmt text).
- **Elasticsearch `_search`/`_msearch`:** mask by key name only, walking
  each hit's `_source` — no regex pass.

Rules live in the file at `RULES_PATH` (`configs/rules.yaml` by default in
this repo and in the Docker image); restart the process after editing — no
rebuild needed. See `configs/rules.example.yaml` for a minimal template, or
`/test-me` (see above) to try changes against a real log line before
committing them.

## Health

`GET /healthz` → `ok`
