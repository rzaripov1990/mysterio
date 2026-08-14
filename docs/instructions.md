# mysterio — инструкция

Маскирующий reverse-proxy перед Loki и/или Elasticsearch: чувствительные
данные в логах маскируются «на лету», прежде чем попадут в Grafana. Grafana
ходит не напрямую в Loki/Elasticsearch, а через mysterio.

---

## 1. Как работает сервис

```
Grafana ──HTTP(S)──▶ mysterio ──HTTP(S)──▶ Loki / Elasticsearch (upstream)
                         │
                         └── маскирует чувствительные поля в ответе
```

- **Reverse-proxy, два независимых бэкенда.** `/loki/*` проксируется на
  `LOKI_URL`, `/elastic/*` — на `ELASTIC_URL`. Префикс маршрута mysterio
  (`/loki` или `/elastic`) отрезается; для Loki путь к upstream ещё
  нормализуется (см. ниже «Префиксы `/loki`»). Каждый бэкенд включается
  отдельно (`LOKI_ENABLED`, `ELASTIC_ENABLED`) — можно держать только Loki,
  только Elasticsearch, или оба сразу. Заголовки авторизации
  (`Authorization`, Basic Auth) **передаются как есть** для обоих бэкендов —
  сервис не хранит и не подменяет учётные данные.
- **Health-check.** `GET /healthz` → `ok`. Используется для liveness/readiness.
- **Маскирование ответа Loki.** Обрабатывается только тело ответа. Сервис:
  - пропускает без изменений ответы со статусом `>= 400`, websocket-апгрейды
    и тела больше `MAX_RESPONSE_BYTES`;
  - при необходимости распаковывает `gzip` (и убирает `Content-Encoding`);
  - обрабатывает только JSON (`Content-Type: *json*` или тело, начинающееся с `{`);
  - находит в ответе строки логов (`data.result[].values[][1]`)
    и применяет к каждой строке правила маскирования (`json_keys` + `regex`).
- **Маскирование ответа Elasticsearch.** Применяется **только** к путям,
  заканчивающимся на `_search` или `_msearch` (после отрезания префикса
  `/elastic`) — остальные эндпоинты (`_mapping`, `_field_caps`, список
  индексов и т.п.) проксируются без изменений и без буферизации тела.
  Для `_search`/`_msearch` сервис разбирает JSON-ответ структурно (обычный
  `{"hits":{"hits":[...]}}` либо `{"responses":[...]}` для `_msearch`) и
  рекурсивно маскирует поля внутри `_source` каждого хита **по имени
  ключа** (`json_keys`) и прогоняет строковые поля (в т.ч. message field
  Grafana вроде `_source.log`) через тот же `Apply`, что и строки Loki —
  embedded JSON + `regex`.
- **Логи самого сервиса.** Пишет только метаданные запроса/ответа (путь,
  статус, `Content-Type`, `Content-Encoding`) — **без содержимого логов и
  без секретов**.

Маскирование строки Loki идёт в два прохода:
1. если строка — валидный JSON (в т.ч. JSON, вложенный/экранированный внутри
   строкового поля), значения ищутся по имени ключа и заменяются рекурсивно;
2. затем применяются регулярные выражения (в т.ч. к строкам, которые не
   парсятся как JSON — SQL, logfmt, query-строки и т.п.).

Для Elasticsearch: по имени ключа рекурсивно в `_source`, плюс `Apply`
(embedded JSON + regex) на **строковых** полях — так маскируется message
field Grafana (`log` / `message`), где лежит текст лога.

Что маскируется по умолчанию (см. `configs/rules.yaml`): ИИН/БИН (HMAC-токен,
см. раздел 5), ФИО, телефоны, e-mail, токены (`Authorization`,
`access_token`, `refresh_token`, Cookie, JWT), учётные данные форм, номера
документов/счетов/карт, IBAN РК, IP-адреса клиента.

### Префиксы `/loki`: Grafana vs upstream

Два разных `/loki` легко перепутать:

| Где | Пример | Смысл |
| --- | --- | --- |
| **URL датасорса в Grafana** | `http://mysterio:8080/loki` | Вход в mysterio (Grafana **не** должна ходить в Loki напрямую) |
| **`LOKI_URL`** | `https://loki.example/loki` | Базовый URL upstream Loki / gateway |

Grafana в зависимости от версии и того, заканчивается ли URL датасорса на
`/loki`, может вызвать либо `/loki/api/v1/...`, либо `/loki/loki/api/v1/...`.
mysterio один раз срезает свой mount `/loki`, затем:

- если в `LOKI_URL` есть path (`https://host/loki`) — это префикс upstream;
  оба варианта Grafana нормализуются в `/loki/api/v1/...`;
- если path в `LOKI_URL` **нет** (`https://host`) — путь после strip
  уходит как есть. При двойном префиксе Grafana
  (`/loki/loki/api/...` → `/loki/api/...`) это совпадает с gateway под
  `/loki`. Надёжнее сразу задать `LOKI_URL=https://host/loki`, чтобы
  работал и одиночный `/loki/api/...`.

**Типичный симптом неверного upstream path:** в Grafana
`unknown result type:` / не грузятся labels, в логах mysterio
`status=404 content_type=text/plain` и тело `404 page not found`.
Чините `LOKI_URL` (нужен ли суффикс `/loki`), URL датасорса Grafana
(`…/mysterio/loki`) не меняйте.

Пример с вашим ingress (`/mysterio` → rewrite в mysterio):

- Grafana datasource: `https://dev-svc.kmf.kz/mysterio/loki`
- Ingress отдаёт в под: `/loki/...` или `/loki/loki/...`
- `LOKI_URL` должен быть вида `https://<loki-gateway>/loki`

---

## 2. Настройка сервиса (переменные окружения)

| Переменная | Обязательна | По умолчанию | Описание |
| --- | --- | --- | --- |
| `LOKI_ENABLED` | нет | `false` | Включает маршрут `/loki/*` |
| `LOKI_URL` | да, если `LOKI_ENABLED=true` | — | Базовый URL upstream Loki. Если Loki за gateway с префиксом `/loki`, укажите его в URL: `https://loki-prod.example/loki`. Для «голого» Loki на `/api/v1` — без path: `http://loki:3100` |
| `ELASTIC_ENABLED` | нет | `false` | Включает маршрут `/elastic/*` |
| `ELASTIC_URL` | да, если `ELASTIC_ENABLED=true` | — | Базовый URL upstream Elasticsearch |
| `ELASTIC_MESSAGE_FIELD` | нет | пусто | Имя message field как в Grafana Logs. Пусто = весь `_source` (дефолт Grafana); `log` — если в датасорсе Message field name = `log` |
| `RULES_PATH` | да | — | Путь к YAML-файлу с правилами маскирования; читается один раз при старте |
| `PORT` | нет | `:8080` | Адрес и порт прослушивания |
| `MAX_RESPONSE_BYTES` | нет | `33554432` (32 MiB) | Ответы больше этого размера проксируются **без** маскирования (общий лимит на оба бэкенда) |
| `TEST_ME_ENABLED` | нет | `false` | Включает страницу предпросмотра маскирования `/test-me` |
| `MASK_HMAC_KEY` | да, если в правилах есть `{hmac}` | — | Сырой HMAC-ключ (минимум 32 байта). Генерация: `openssl rand -base64 32`. Не логировать, не класть в `rules.yaml` |
| `BASE_PATH` | нет | пусто (корень) | Префикс путей **только** для `/test-me` (например `/mysterio`); на `/loki`, `/elastic`, `/healthz` не влияет — если сервис висит за внешним reverse-proxy не на корне, префиксацию этих маршрутов решает он |

Сервис не стартует (падает с ошибкой при старте), если:
- **ни один** из `LOKI_ENABLED`/`ELASTIC_ENABLED` не выставлен в `true`;
- включённый бэкенд (`LOKI_ENABLED=true` или `ELASTIC_ENABLED=true`) не имеет
  соответствующего `*_URL`, либо URL не парсится;
- `MAX_RESPONSE_BYTES` задан некорректно;
- `BASE_PATH` задан, но не начинается с `/` или заканчивается на `/`;
- `RULES_PATH` пуст, файл по этому пути не существует/не читается, либо его
  содержимое — невалидный YAML, невалидный regex, неизвестный `normalize`,
  либо некорректный плейсхолдер `{hmac}` / `{hmac:$N}`;
- в правилах есть `{hmac}`, но `MASK_HMAC_KEY` не задан или короче 32 байт.

Правила маскирования читаются из файла по пути `RULES_PATH` **один раз при
старте процесса** — hot-reload нет, изменения требуют перезапуска.

### Запуск из исходников

```bash
export LOKI_ENABLED=true
# Gateway с /loki; для native Loki: http://loki:3100 (без path).
export LOKI_URL=https://loki-prod.example/loki
export RULES_PATH=./configs/rules.yaml
export MASK_HMAC_KEY=$(openssl rand -base64 32)
export PORT=:8080
go run .
```

### Запуск бинарника

```bash
go build -buildvcs=false -o bin/mysterio .
LOKI_ENABLED=true LOKI_URL=https://loki-prod.example/loki \
  RULES_PATH=./configs/rules.yaml \
  MASK_HMAC_KEY="$(openssl rand -base64 32)" \
  ./bin/mysterio
```

### Запуск в Docker

```bash
docker build -t mysterio .
docker run --rm -p 9999:8080 \
  -e LOKI_ENABLED=true \
  -e LOKI_URL=https://loki-prod.example/loki \
  -e MASK_HMAC_KEY="$(openssl rand -base64 32)" \
  mysterio
```

Чтобы включить также Elasticsearch, добавьте `-e ELASTIC_ENABLED=true -e ELASTIC_URL=...`.

Образ содержит дефолтные правила (`configs/rules.yaml`, путь `RULES_PATH`
задан в образе). Чтобы использовать свои правила без пересборки —
смонтируйте файл поверх этого пути:

```bash
docker run --rm -p 9999:8080 \
  -e LOKI_ENABLED=true \
  -e LOKI_URL=https://loki-prod.example/loki \
  -e MASK_HMAC_KEY="$(openssl rand -base64 32)" \
  -v $(pwd)/configs/rules.yaml:/etc/mysterio/rules.yaml:ro \
  mysterio
```

Изменения в файле на хосте применяются после перезапуска контейнера.

Проверка: `curl http://localhost:9999/healthz` → `ok`.

---

## 3. Датасорсы в Grafana (внешняя Grafana)

Внешняя (уже развёрнутая) Grafana должна указывать на **mysterio**, а не на
Loki/Elasticsearch напрямую — иначе маскирование обходится.

### Loki

1. Разверните mysterio так, чтобы он был **сетево доступен из Grafana**
   (например, `https://mysterio.example` или `http://<host>:9999`).
2. В Grafana: **Connections → Data sources → Add data source → Loki**.
3. Заполните:
   - **URL** — адрес mysterio **с префиксом `/loki`**, напр.
     `https://mysterio.example/loki` (НЕ адрес Loki и НЕ корень mysterio).
     Этот `/loki` — маршрут **в mysterio**, его не путать с path в
     `LOKI_URL` (см. «Префиксы `/loki`» выше).
   - **Authentication** — если upstream Loki требует Basic Auth, включите
     **Basic authentication** и укажите логин/пароль. mysterio передаёт их
     в Loki без изменений.
   - при необходимости **Skip TLS verify** (для self-signed сертификатов).
4. **Save & test**. Если тест падает с `unknown result type:`, проверьте
   `LOKI_URL` на стороне mysterio (нужен ли суффикс `/loki` у gateway), а не
   URL датасорса в Grafana.

### Elasticsearch

Аналогично, но:
- **Connections → Data sources → Add data source → Elasticsearch**.
- **URL** — адрес mysterio **с префиксом `/elastic`**, напр.
  `https://mysterio.example/elastic`.
- Маскируются только ответы `_search`/`_msearch` (обычные запросы Grafana
  за логами); служебные запросы (список индексов, `_field_caps` для
  автокомплита полей) проксируются как есть.

> Важно: URL — это точка входа mysterio (с нужным префиксом), а не адрес
> Loki/Elasticsearch напрямую. Убедитесь, что это не публичный адрес
> upstream и не `localhost` внутри чужого контейнера.

### Вариант через provisioning (файл)

Если внешняя Grafana конфигурируется провиженингом, датасорс задаётся файлом
`provisioning/datasources/*.yml`. Секреты — только через переменные окружения
Grafana (`$LOKI_USER` / `$LOKI_PASS`), не в открытом виде:

```yaml
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    uid: loki
    url: https://mysterio.example/loki   # адрес mysterio, с префиксом /loki
    isDefault: true
    basicAuth: true
    basicAuthUser: $LOKI_USER
    jsonData:
      maxLines: 1000
      timeout: 60
      tlsSkipVerify: true              # если сертификат self-signed
    secureJsonData:
      basicAuthPassword: $LOKI_PASS
```

> В комплекте есть готовый локальный стенд (`docker-compose.yml` + `run.sh`) с
> Grafana и датасорсом. Там Grafana обращается к `http://mysterio:8080/loki`
> по внутренней сети compose. Для **внешней** Grafana используйте внешний
> адрес mysterio, как описано выше.

---

## 4. Правила маскирования

### Где хранятся

- Путь к файлу правил задаётся переменной `RULES_PATH` (обязательна) —
  сервис читает файл один раз при старте (`os.ReadFile` в `config.Load()`,
  `configs/config.go`).
- Изменения применяются только после **перезапуска процесса/контейнера** —
  hot-reload нет; правки файла на диске сами по себе не подхватываются.
- В Docker-образе по умолчанию лежит `configs/rules.yaml` (скопирован на
  этапе сборки), `RULES_PATH` в образе указывает на него — образ работает
  без внешнего volume. Для локального стенда (`docker-compose.yml`) этот
  путь смонтирован поверх файлом `configs/rules.yaml` из репозитория, так
  что правки применяются через `docker compose restart mysterio`, без
  пересборки образа.
- Регулярные выражения проверяются на компиляцию при старте сервиса; невалидный
  паттерн (или отсутствующий/нечитаемый файл) не даст сервису стартовать.
- Одни и те же правила используются для обоих бэкендов: `json_keys` по
  структуре, `regex` — для строк Loki и строковых полей `_source` в Elastic.

### Структура файла

Два механизма — `json_keys` и `regex`:

```yaml
json_keys:
  - name: iin                       # человекочитаемое имя правила
    keys: [iin, IIN, biin, BIIN]    # имена ключей (регистр важен!)
    replace: "{hmac}"               # "***" или "{hmac}" / "{hmac:$N}"
    normalize: digits               # опционально: none | digits | lower

regex:
  - name: email
    pattern: '...'                  # регулярное выражение (Go RE2)
    replace: "***@***"              # строка замены ($1, ${1}, {hmac}, {hmac:$N})
```

### Когда использовать `json_keys`

Механизм маскирует **скалярное значение по точному имени ключа**, рекурсивно.
Для Loki — в том числе внутри JSON, вложенного/экранированного в строковое
поле (`...\"iin\":\"...\"...`), и сервис сам строит текстовые паттерны для
формы `"key":"value"` в не-JSON строках. Для Elasticsearch — рекурсивно по
объекту `_source` каждого хита в `_search`/`_msearch`.

Подходит, когда:
- значение — **скаляр** (строка/число), а не объект;
- достаточно совпадения по имени ключа.

Особенности:
- **регистр важен**: `iin` и `IIN` — разные ключи, перечисляйте все варианты;
- **объекты не маскируются**: если значение — `{...}`, `json_keys` пойдёт
  внутрь по вложенным ключам, но сам объект не заменит (для этого нужен
  `regex` — в т.ч. внутри строкового поля `_source.log` у Elasticsearch).
- **`{hmac}`** вместо звёздочек: keyed HMAC-токен (`~` + 11 символов
  base64url) от нормализованного значения. Один и тот же ИИН даёт один
  токен в любом поле и бэкенде. `normalize: digits | lower | none`
  (по умолчанию `none` = trim). Это псевдонимизация, не шифрование —
  обратно не восстановить. Нужен `MASK_HMAC_KEY`.

Примеры из `configs/rules.yaml`:

```yaml
json_keys:
  # ИИН/БИН клиента во всех вариантах написания ключа
  - name: iin
    keys: [iin, IIN, biin, BIIN, bin, iinBin, CLIENT_BIIN]
    replace: "{hmac}"
    normalize: digits

  # токены — заменяем значение целиком
  - name: tokens
    keys: [Authorization, access_token, refresh_token, Cookie, Set-Cookie]
    replace: "***"
```

```
{"IIN":"123456123456"}              → {"IIN":"~Ab3xK9pQ_dE"}
{"data":{"biin":"123456123456"}}    → {"data":{"biin":"~Ab3xK9pQ_dE"}}   (рекурсивно)
```

### Когда использовать `regex`

Механизм — замена по регулярному выражению поверх (пере)сериализованной
строки. Для Loki — к каждой log line; для Elasticsearch — к строковым
полям `_source` (в т.ч. message field). Если паттерн содержит
кавычку, сервис **автоматически** компилирует и применяет экранированный
вариант (`\"key\":\"val\"`), поэтому одно правило покрывает и обычный JSON,
и JSON, экранированный внутри строки.

Подходит, когда:
- значение имеет **формат**, а не привязано к ключу (e-mail, телефон, JWT, IBAN, IP);
- значение — **объект**, который надо схлопнуть целиком (ФИО `{KZ,RU,EN}`);
- данные встречаются в **не-JSON** строках (SQL, logfmt, query-строки, «голый»
  номер в URL).

Замена поддерживает обратные ссылки `$1` / `${1}` — так можно сохранить имя ключа.
Плейсхолдер `{hmac}` хеширует всё совпадение; `{hmac:$N}` — только группу N.

Примеры из `configs/rules.yaml`:

```yaml
regex:
  # формат: e-mail
  - name: email
    pattern: '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    replace: "***@***"

  # формат: ИИН/БИН как «голые» 12 цифр — ловит не-JSON случаи
  # (iin=..., SQL, номер в URL). \b исключает 10/13-значные таймстампы.
  - name: iin_bin_bare
    pattern: '\b\d{12}\b'
    replace: "{hmac}"
    normalize: digits

  # формат: JWT (три base64url-сегмента) — где бы ни встретился
  - name: jwt
    pattern: 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    replace: "***"

  # объект: ФИО в любой обёртке ({KZ,RU,EN} или {"value":..,"type":..})
  # либо строка — схлопываем значение целиком, имя ключа сохраняем через $1
  - name: fullName
    pattern: '"(FULLNAME|fullName)"\s*:\s*(?:\{[^}]*\}|"[^"]*")'
    replace: '"${1}":"***"'
```

```
iin=123456123456                          → iin=~Ab3xK9pQ_dE
WHERE iin = '123456123456'                → WHERE iin = '~Ab3xK9pQ_dE'
"fullName":{"RU":"Шлтев Мутар ..."}        → "fullName":"***"
"Authorization":"Bearer eyJ...."           → "Authorization":"***"
```

### Как выбрать механизм — кратко

| Ситуация | Механизм | Бэкенды |
| --- | --- | --- |
| Скаляр по имени ключа (`iin`, `access_token`) | `json_keys` | Loki, Elasticsearch |
| Нужна корреляция (найти все логи одного ИИН) | `json_keys`/`regex` с `{hmac}` | Loki, Elasticsearch |
| Значение по формату (e-mail, телефон, JWT, IBAN, IP) | `regex` | Loki; Elastic — в строковых полях `_source` |
| Объект-значение целиком (`{KZ,RU,EN}`, `{value,type}`) | `regex` | Loki; Elastic — в строковых полях `_source` |
| Данные в не-JSON строках (SQL, logfmt, query, `_source.log`) | `regex` | Loki, Elasticsearch |
| Нужно сохранить имя ключа в выводе | `regex` с `$1`/`${1}` | Loki; Elastic — в строковых полях |

### Как добавить новое правило

1. Определите: значение привязано к **ключу** (→ `json_keys`) или к
   **формату/объекту/не-JSON** (→ `regex`). Оба механизма работают и для
   Loki, и для строковых полей Elasticsearch `_source` (message field).
2. Добавьте запись в соответствующую секцию `configs/rules.yaml`.
   Для корреляции (ИИН, телефон) ставьте `replace: "{hmac}"` и тот же
   `normalize` на всех правилах, которые должны давать один токен
   (json_keys `iin` и regex `iin_bin_bare` — оба `digits`).
3. **Перезапустите** процесс/контейнер (`RULES_PATH` читается один раз при
   старте, пересборка не нужна) — либо сначала проверьте правило без
   перезапуска через `/test-me` (см. раздел 6).
4. Проверьте на реальной строке лога, что значение замаскировано, а не-целевые
   данные не затронуты (осторожно с широкими `regex` — возможны ложные
   срабатывания).

---

## 5. HMAC-токены: ключ и поиск в Grafana

Дефолтные правила ИИН/БИН (`iin` и `iin_bin_bare`) заменяют значение не на
звёздочки, а на стабильный токен вида `~Ab3xK9pQ_dE`. Один и тот же номер
даёт один токен в JSON-поле, в SQL и в URL — и в Loki, и в Elasticsearch.
По токену можно сгруппировать логи одного человека, не видя ИИН.

Это **keyed hash (псевдонимизация), не шифрование**. Обратно в ИИН токен
не восстановить. Пароли, JWT, ФИО, e-mail по умолчанию по-прежнему `***`.

### Ключ `MASK_HMAC_KEY`

1. Сгенерируйте один раз и сохраните в секрет хранилища (не в git):

   ```bash
   openssl rand -base64 32
   ```

   Минимум 32 байта; значение берётся **как есть** (не hex-decode).
2. Передайте в процесс: env, docker `-e`, compose `MASK_HMAC_KEY: ${MASK_HMAC_KEY}`.
   В `docker-compose.yml` дефолта нет — без переменной на хосте сервис
   не стартует, пока в правилах есть `{hmac}`.
3. Не кладите ключ в `rules.yaml`, не коммитьте, не пишите в логи mysterio.

Утечка ключа + перебор 12-значного ИИН снимает псевдонимизацию. **Ротация
ключа** делает старые токены несовместимыми с новыми: джойн «старый лог +
новый лог» по токену перестанет работать. Меняйте ключ только если это
осознанно.

### Как добавить `{hmac}` в правило

```yaml
json_keys:
  - name: iin
    keys: [iin, IIN, biin]
    replace: "{hmac}"
    normalize: digits          # none | digits | lower; по умолчанию none

regex:
  - name: iin_bin_bare
    pattern: '\b\d{12}\b'
    replace: "{hmac}"          # всё совпадение
    normalize: digits
  - name: named
    pattern: '"(k)"\s*:\s*"([^"]*)"'
    replace: '"${1}":"{hmac:$2}"'   # хешировать только группу 2
```

- `{hmac:$N}` в `json_keys` запрещён — хешируется весь скаляр.
- `null` / `bool` / пустая строка / уже замаскированное `***` → `***`, не токен.
- Поля, которые хотите джойнить, должны иметь **одинаковый `normalize`**.
  Иначе `"iin":"+7701…"` и `7701…` дадут разные токены.

### Найти логи по известному ИИН

1. Откройте `/test-me` (`TEST_ME_ENABLED=true`).
2. Блок **Lookup token for Grafana**: вставьте ИИН, `normalize` = как в
   правиле (`digits` для ИИН), **Hash**, **Copy**.
3. В Grafana Explore вставьте токен как **точное совпадение**, в кавычках:

   - Loki: `{k8s_app="…"} |= "~Ab3xK9pQ_dE"`
   - Elasticsearch: query string с кавычками, `"~Ab3xK9pQ_dE"`
     (не `|~` без кавычек: в LogQL `~` — оператор regex).

Ключ на страницу не отдаётся. `/test-me` умеет посчитать токен для любого
известного значения — не выставляйте её за пределы доверенной сети.

---

## 6. Тестовая страница `/test-me`

Страница для проверки правил маскирования без пересборки и без риска для
прод-конфигурации сервиса.

- Включается `TEST_ME_ENABLED=true` (по умолчанию выключена). Доступна на
  `/test-me`, либо на `{BASE_PATH}/test-me`, если задан `BASE_PATH`.
- Редактор `rules.yaml` (на базе [CodeMirror 5](https://codemirror.net/5/),
  MIT, вендорится в бинарь через `go:embed` — без CDN и внешних сетевых
  запросов) предзаполняется реальными правилами, встроенными в текущий
  бинарь.
- **Правки в редакторе не применяются к работающему сервису.** По кнопке
  «Mask» текст правил и строка лога отправляются на бэкенд, там поднимается
  одноразовый парсер правил и маскер, результат возвращается и отображается
  — «боевой» маскер сервиса при этом не трогается.
- Lookup HMAC-токена для Grafana — см. раздел 5. Ключ на страницу не
  отдаётся; не выставляйте `/test-me` за пределы доверенной сети
  (встроенной авторизации нет).

Пример: `TEST_ME_ENABLED=true LOKI_ENABLED=true LOKI_URL=... \
  MASK_HMAC_KEY=... go run .`, затем открыть `http://localhost:8080/test-me`.
