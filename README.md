# mysterio

A masking reverse-proxy that sits between Grafana and your log/observability
backends. Grafana talks to **mysterio**, never directly to Loki or
Elasticsearch — mysterio forwards the request, and on the way back masks
sensitive fields (IIN/BIN, names, phones, e-mails, tokens, card/account
numbers, IPs, etc.) in the response before Grafana ever sees it.

```
Grafana ──HTTP(S)──▶ mysterio ──HTTP(S)──▶ Loki / Elasticsearch (upstream)
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
  mysterio does not store or substitute credentials.
- mysterio's own logs contain only request metadata (path, status,
  content-type) — never log content or secrets.
- An optional `/test-me` page lets you paste a candidate `rules.yaml` and a
  log line and preview the masked result, without touching the live rules.

## Run

```bash
export LOKI_ENABLED=true
# Include /loki when the upstream gateway serves under that prefix.
export LOKI_URL=https://loki-dev.example/loki
export RULES_PATH=./configs/rules.yaml
export PORT=:8080

go run .
```

Or:

```bash
go build -o bin/mysterio .
./bin/mysterio
```

At least one of `LOKI_ENABLED`/`ELASTIC_ENABLED` must be `true`, or the
process exits at startup with an error — this includes the docker-compose
stack below, whose defaults leave both `false`.

## Env

| Variable | Default | Description |
| --- | --- | --- |
| `LOKI_ENABLED` | `false` | Enable the `/loki` proxy route |
| `LOKI_URL` | — | Upstream Loki base URL; required if `LOKI_ENABLED=true`. Use `https://host/loki` when Loki is behind a `/loki` gateway prefix |
| `ELASTIC_ENABLED` | `false` | Enable the `/elastic` proxy route |
| `ELASTIC_URL` | — | Upstream Elasticsearch base URL; required if `ELASTIC_ENABLED=true` |
| `ELASTIC_MESSAGE_FIELD` | `` (empty) | Grafana "Message field name". Empty = whole `_source` (Grafana default); set to `log` when the datasource uses Message field name `log` |
| `PORT` | `:8080` | Listen address |
| `MAX_RESPONSE_BYTES` | `33554432` | Skip masking above this size (shared by both backends) |
| `TEST_ME_ENABLED` | `false` | Enable the `/test-me` masking-preview UI |
| `BASE_PATH` | `` (root) | Path prefix for `/test-me` only (e.g. `/mysterio`); does not affect `/loki`, `/elastic`, `/healthz` |
| `RULES_PATH` | — | Path to the masking rules YAML file; required, loaded once at startup |

Masking rules are loaded from the file at `RULES_PATH` **once, at process
startup** — there is no hot-reload. To change rules, edit the file and
restart the process (or `docker compose restart mysterio` — no image rebuild
needed if the file is bind-mounted, see below). The same rules apply to both
Loki and Elasticsearch: `json_keys` rules mask matching keys recursively in
both; the `regex` rules apply to Loki log lines and to string fields inside
Elasticsearch `_source` (e.g. Grafana's message field `log`).

## Routing

- `/loki/*` → forwarded to `LOKI_URL` (mysterio mount prefix `/loki` is
  stripped, then the upstream path is normalized — see below)
- `/elastic/*` → forwarded to `ELASTIC_URL` (prefix stripped); response
  masking is applied only to `_search`/`_msearch` responses — other
  Elasticsearch endpoints (`_mapping`, `_field_caps`, index listings) pass
  through unmodified.
- `/healthz` → `ok`

### Loki path prefixes (Grafana vs upstream)

Two different `/loki` prefixes are easy to confuse:

| Where | Example | Meaning |
| --- | --- | --- |
| **Grafana datasource URL** | `http://mysterio:8080/loki` | Route into mysterio (do **not** point Grafana at Loki directly) |
| **`LOKI_URL`** | `https://loki.example/loki` | Upstream Loki/gateway base URL |

Grafana may call either `/loki/api/v1/...` or `/loki/loki/api/v1/...`
(depends on Grafana version and whether the datasource URL already ends
with `/loki`). mysterio strips its mount prefix once, then:

- If `LOKI_URL` includes a path (e.g. `https://host/loki`), that path is
  the upstream prefix: both Grafana styles are normalized to
  `/loki/api/v1/...`.
- If `LOKI_URL` has **no** path (e.g. `https://host`), the path after
  strip is forwarded as-is. With Grafana double-prefix
  (`/loki/loki/api/...` → `/loki/api/...`) this matches gateways under
  `/loki`. Prefer setting `LOKI_URL=https://host/loki` so single-prefix
  Grafana also works.

**Symptom of a wrong upstream path:** Grafana shows
`Status: 500. Message: unknown result type:` or label browser fails,
while mysterio logs `upstream ... status=404 content_type=text/plain`
and body `404 page not found`. Fix `LOKI_URL` (include `/loki` when the
gateway needs it) — do **not** change the Grafana datasource URL.

## Masking test UI

Set `TEST_ME_ENABLED=true` to expose `/test-me` (or `{BASE_PATH}/test-me` if
`BASE_PATH` is set): a page to paste a candidate `rules.yaml` and a log line,
and preview the masked result. The rules editor is prefilled with the
service's actual embedded rules, but **edits there are never applied to the
running service** — each preview parses the submitted rules fresh and
discards them. Off by default; not intended to be exposed outside a
trusted network (mysterio has no built-in auth).

The YAML editor uses [CodeMirror 5](https://codemirror.net/5/) (MIT
licensed), vendored under `internal/testme/vendor/` and served by mysterio
itself via `go:embed` — no CDN, no network calls from the browser other than
back to mysterio.

## Local Grafana (docker compose)

Grafana and mysterio run in one compose network. Loki datasource URL is
`http://mysterio:8080/loki` — **not** `localhost` / `0.0.0.0` (those point
inside the Grafana container).

```bash
export LOKI_ENABLED=true
# Gateway with /loki prefix — native Loki would be http://loki:3100 (no path).
export LOKI_URL=https://loki-prod.example/loki
./run.sh
# or: docker compose up -d --build
```

- Grafana: http://localhost:3000 (admin/admin)
- Proxy on host: http://localhost:9999/healthz
- Masking test UI (on by default in compose): http://localhost:9999/test-me
- Request logs: `docker compose logs -f mysterio`
- Rules: bind-mounted from `configs/rules.yaml` — edit that file and run
  `docker compose restart mysterio` to apply, no rebuild needed.

Open dashboard **mysterio Logs**.

To also proxy Elasticsearch, set `ELASTIC_ENABLED=true` and `ELASTIC_URL=...`
before running `./run.sh` (see `docker-compose.yml`), then add a Grafana
Elasticsearch datasource pointed at `http://mysterio:8080/elastic`.

Variables (examples):
- `namespace` (`k8s_namespace`) — custom list of namespaces
- `k8s_app` — `label_values({k8s_namespace_name=~"$namespace"}, k8s_app)`
- `query1` / `or` / `query2` / `query3` — textbox filters (default `.*`)

Panel LogQL:

```logql
{k8s_namespace_name="$namespace", k8s_app=~"$k8s_app"} |~ "$query1|$or" |~ "$query2" |~ "$query3"
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
- **Elasticsearch `_search`/`_msearch`:** mask by key name in `_source`, and
  run the same Apply path (embedded JSON + regex) on string fields such as
  Grafana's message field (`log` / `message`).

Rules live in the file at `RULES_PATH` (`configs/rules.yaml` by default in
this repo and in the Docker image); restart the process after editing — no
rebuild needed. See `configs/rules.example.yaml` for a minimal template, or
`/test-me` (see above) to try changes against a real log line before
committing them.

## Health

`GET /healthz` → `ok`
