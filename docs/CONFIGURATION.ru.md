# Настройка Raddy

[English](CONFIGURATION.md) · [Главная](../README.ru.md) · [Пример Raddyfile](../Raddyfile) · [Пример JSON](../raddy.example.json)

## Возможности

- HTTP/1.1 и HTTP/2, TLS 1.2/1.3 и выбор сертификата по SNI.
- Streaming proxy и файлов: тела не буферизуются целиком.
- Zero-copy `sendfile` для plaintext HTTP/1.1 статики на macOS/Linux. На Linux мелкие файлы отправляются вместе с заголовком, а крупные передаются с асинхронным ожиданием готовности сокета. Кэш открытых файлов и тел малых файлов; путь открывается относительно root без перехода по символическим ссылкам.
- HTTP, HTTPS и h2c upstream, keep-alive пулы, балансировка round-robin или `first`, активная проверка backend и ограниченные повторы безопасных запросов.
- Автоматический ACME DNS-01, wildcard-сертификаты, ожидание распространения TXT, очистка challenge и продление за 30 дней.
- Постоянное хранение ACME account, ключей и сертификатов; атомарная запись ключей с правами `0600` на Unix.
- Cloudflare: get/append/set/delete, список зон, пагинация, кэш зон, два токена, retry для 429/5xx и параллельные запросы.
- Совместимы форматы токенов caddy-dns/cloudflare: `api_token`, `zone_token` и подстановка `{env.NAME}`.
- TCP streams и TLS passthrough по SNI: отдельные порты или общий порт с HTTPS, round-robin upstream, idle/connect/handshake таймауты. TLS handshake и шифрование остаются end-to-end с backend.
- Caddyfile/Raddyfile: автоматический HTTPS, Cloudflare DNS, reverse proxy, статика и response headers. Короткий `tls://sni:port`/`tcp://listen:port` для Layer 4, плюс совместимый `layer4`. Кавычки, комментарии и `{env.NAME}` поддерживаются.

## Запуск

```sh
export CF_API_TOKEN='ваш-scoped-api-token'
cargo run --release -- --config Raddyfile validate
cargo run --release -- --config Raddyfile run
```

Если `--config` не задан, выбираются `raddy.json`, `Raddyfile`, `Caddyfile` в этом порядке. Путь с расширением `.json` разбирается как JSON, остальные — как Caddyfile. Для запуска используется один файл: смешивать JSON и Caddyfile нельзя.

Токен `CF_API_TOKEN` должен иметь права **Zone:Read** и **DNS:Edit**. Для раздельного доступа добавьте `zone_token` с **Zone:Read**, а основному токену оставьте **DNS:Edit**. Секреты лучше передавать через окружение, а не записывать напрямую в конфигурацию.

## Docker

Соберите образ из исходников или скачайте архив для `linux/amd64` либо `linux/arm64` из раздела Releases и загрузите его через `docker load`. Видимость пакета GHCR настраивается отдельно от репозитория.

```sh
docker build -t raddy:local .
docker run --rm --name raddy -p 80:80 -p 443:443 \
  --mount type=bind,src="$PWD/Raddyfile",dst=/etc/raddy/Raddyfile,readonly \
  --mount type=volume,src=raddy-data,dst=/data \
  --env CF_API_TOKEN raddy:local
```

Перед запуском адаптируйте `Raddyfile`: адреса upstream должны быть доступны из контейнера, а для статики нужно смонтировать каталог. Для дополнительных TCP listener публикуйте соответствующие порты отдельными `-p`. Сертификаты и ACME-аккаунт храните в `/data`; монтируемые конфиг и сертификаты должны быть доступны для чтения UID `10001`. `CF_API_TOKEN` нужен только при использовании Cloudflare и передаётся из окружения хоста. Для локальной сборки: `docker build -t raddy:local .`.

### Docker Compose (Linux, сеть хоста)

Сохраните `compose.yaml` рядом с вашим `Raddyfile`:

```yaml
services:
  raddy:
    image: ghcr.io/rawtls/raddy:v0.4.1
    container_name: raddy
    restart: unless-stopped
    stop_grace_period: 35s
    network_mode: host
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    environment:
      - CF_API_TOKEN
    volumes:
      - ./Raddyfile:/etc/raddy/Raddyfile:ro
      - raddy-data:/data

volumes:
  raddy-data:
```

Подготовьте свой `Raddyfile` и запустите:

```sh
docker compose run --rm raddy validate
docker compose up -d
```

В режиме `host` секция `ports:` не нужна: Raddy слушает порты прямо на хосте. Проверьте, что они свободны, и ограничьте доступ к внутренним портам через `bind` или файрвол. Если Xray работает на том же Linux-хосте, upstream `127.0.0.1:10001` будет указывать на него, а не на отдельную сеть контейнера.

Для Cloudflare DNS-01 положите `.env` рядом с `compose.yaml` и запускайте Compose из этого каталога:

```dotenv
CF_API_TOKEN=ваш_токен_Cloudflare
```

Не коммитьте `.env`. Если переменная уже экспортирована в оболочке, её значение имеет приоритет. В `Raddyfile` укажите `api_token {env.CF_API_TOKEN}` в блоке `cloudflare` и храните данные под `/data` (например, `data_dir /data/raddy-data`). Без Cloudflare токен не нужен. Если образ из GHCR недоступен, в клоне репозитория замените `image:` на `build: .` и выполните `docker compose build`.

Минимальная конфигурация для HTTP без Cloudflare:

```json
{
  "http_addr": "127.0.0.1:8080",
  "sites": [{"hosts": ["localhost"], "tls": false, "root": "./public"}]
}
```

### Поля

- `http_addr`, `https_addr`: адреса прослушивания, по умолчанию `:80`, `:443`.
- `email`: контакт для нового ACME account.
- `acme_ca`: URL ACME directory; по умолчанию production Let's Encrypt. Для тестирования используйте `https://acme-staging-v02.api.letsencrypt.org/directory`.
- `data_dir`: ACME accounts и сертификаты, по умолчанию `./raddy-data`.
- `redirect_http`: перенаправление HTTP на HTTPS, по умолчанию `true`.
- `request_timeout_secs`: максимальное ожидание заголовков upstream без продвижения загрузки тела запроса, а затем максимальная пауза при чтении тела ответа (по умолчанию `60`). Передача порций тела запроса продлевает ожидание заголовков; после завершения загрузки у upstream есть этот интервал на ответ. TCP-подключение к HTTP-upstream имеет отдельный лимит 10 секунд. Если заголовки уже отправлены клиенту, таймаут прерывает тело вместо отправки нового статуса `504`.
- `max_header_size`: максимум для HTTP/1 буфера заголовков, по умолчанию `65536`.
- `max_connections`: общий лимит принятых клиентских TCP-соединений на процесс, включая HTTPS, passthrough и WebSocket после Upgrade. `0` (по умолчанию) отключает лимит. В Raddyfile — глобальная опция `max_connections 4096`. При превышении новые соединения закрываются без HTTP-ответа; reload не прерывает уже принятые потоки и не сбрасывает счётчик. Это не лимит файловых дескрипторов или HTTP/2-потоков; оставляйте запас для соединений к backend. При `EMFILE`/`ENFILE` и временных ошибках нехватки буферов приём новых соединений повторяется после паузы.
- `static_cache_entries`: максимум записей на один файловый кэш, по умолчанию `1024`; `0` отключает кэш. На Unix запись может содержать тело файла до 16 КиБ: при настройках по умолчанию это до 16 МиБ тел на кэш, без учёта метаданных и активных ответов. Несколько обработчиков `file_server` могут иметь отдельные кэши. Большие файлы передаются потоком.
- `static_cache_ttl_secs`: TTL файлового кэша, по умолчанию `30`. Для малых файлов значения ETag, метаданных и тела могут оставаться прежними до истечения TTL, даже после замены или удаления файла. При `0` Raddy открывает путь заново для каждого запроса. Для частого обновления статики используйте имена с хэшем содержимого или уменьшите TTL.
- `sites`: массив сайтов.
  - `hosts`: точные имена или `*.example.com`.
  - `upstreams`: origin URL без пути: `http://`, `https://` или `h2c://`.
  - `root`: каталог статики; по умолчанию ищутся `index.html`, `index.htm`.
  - `index`: собственный приоритет index-файлов.
  - `tls`: включить TLS, по умолчанию `true`.
  - `certificate_file`, `private_key_file`: использовать существующие PEM вместо ACME.

`hosts: ["*"]` доступен только при `tls: false`: нельзя выпустить сертификат на произвольный хост. Для production нужны открытые порты 80/443 и публичная DNS-зона Cloudflare. Реальный выпуск сертификатов требует действительных учётных данных и внешней DNS.

## DNS CLI

Можно использовать только `CF_API_TOKEN`, без `raddy.json`:

```sh
export CF_API_TOKEN='ваш-scoped-api-token'
raddy dns zones
raddy dns list example.com
raddy dns add example.com --type TXT _acme-challenge 'значение' --ttl 120
raddy dns set example.com --type A www '192.0.2.1' --ttl 300
raddy dns delete example.com --type TXT _acme-challenge 'значение'
raddy dns challenge www.example.com 'значение-acme'
raddy dns cleanup www.example.com 'значение-acme'
```

`set` ищет запись по имени и типу, затем создаёт или обновляет её через PATCH. `delete` без значения удаляет все совпадения по имени и типу; TXT сопоставляется после RFC 1035 декодирования. При явном значении удаляются только точные совпадения. Пустая строка TXT в значении интерпретируется как wildcard при удалении.

## TCP и TLS passthrough

В Caddyfile/Raddyfile рекомендуется короткий синтаксис `tls://`/`tcp://`:

```caddyfile
# :9443 — порт прослушивания, app.example.com — SNI-маршрут.
tls://app.example.com:9443 {
	proxy 10.0.0.10:443 10.0.0.11:443
}

tls://*.internal.example.com:9443 {
	proxy 10.0.1.10:443
}

# Необязательный fallback для остального SNI.
tls://*:9443 {
	proxy 10.0.2.10:443
}

# Обычный TCP без SNI.
tcp://:5432 {
	proxy 10.0.0.20:5432
}
```

Для TLS все блоки с одним портом объединяются в один listener. Имя до `:port` — только SNI, а не адрес bind. Для TCP `:port` означает `default_bind` (по умолчанию `0.0.0.0`); можно указать `tcp://127.0.0.1:5432`. Для TLS bind задаётся внутри блока: `bind 127.0.0.1`. На общем порту адрес bind должен совпадать, а заданные параметры TLS-инспекции должны совпадать между `tls://` блоками.

`tls://` — **passthrough**, а не HTTPS termination: Raddy читает ClientHello, выбирает backend и передаёт исходные TLS-байты. Приоритет на общем порту: точный SNI, wildcard на одну DNS-метку, затем `tls://*:port`, затем `tcp://`. Одинаковый шаблон одновременно в `tls://` и HTTPS запрещён. Обычный TCP или полноценный ClientHello без подходящего маршрута попадает в TCP fallback, если он настроен. Невалидный или незавершённый ClientHello не переключается на TCP. Если клиент ничего не отправляет, TCP fallback получает соединение после таймаута распознавания TLS (по умолчанию 10 с); для протоколов, где сервер говорит первым, лучше использовать отдельный порт. Несколько upstream используют round-robin.

В сборках новее `v0.2.0` общий порт выглядит так:

```caddyfile
tls://test.example.com:443 {
    proxy 127.0.0.1:10002
}

*.example.com {
    respond "HTTPS"
}

tcp://:443 {
    proxy 127.0.0.1:10003
}
```

Для HTTPS укажите Cloudflare DNS-01 или PEM, как в обычном HTTPS-сайте. `tcp://` необязателен: без него обычный TCP и неизвестные TLS-имена не передаются backend.

Поля внутри блока: `proxy`, `bind`, `connect_timeout`, `idle_timeout`, `handshake_timeout`, `max_handshake_bytes`. Для TCP доступны только `proxy`, `bind`, `connect_timeout` и `idle_timeout`: handshake-настройки относятся только к TLS. Необязательные значения: 10s, 5m, 10s и 16384 соответственно.

Старый синтаксис `layer4` также поддерживается; для общего порта проще использовать отдельные `tls://` и `tcp://` блоки. Полный пример — `Raddyfile`.

Для JSON TCP и TLS passthrough задаются отдельно от HTTP `sites` в массиве `streams`. Они могут работать вместе с HTTP или отдельно, без занятия портов 80/443.

```json
{
  "sites": [],
  "streams": [
    {
      "listen": "0.0.0.0:9443",
      "type": "tls_passthrough",
      "routes": [
        {"sni": "app.example.com", "upstreams": ["10.0.0.10:443", "10.0.0.11:443"]},
        {"sni": "*.internal.example.com", "upstreams": ["10.0.1.10:443"]},
        {"sni": "*", "upstreams": ["10.0.2.10:443"]}
      ]
    },
    {
      "listen": "0.0.0.0:5432",
      "type": "tcp",
      "routes": [{"upstreams": ["10.0.0.20:5432"]}]
    }
  ]
}
```

- `type: "tcp"`: одна default route, никакого SNI; поддерживаются любые TCP-протоколы.
- `type: "tls_passthrough"`: Raddy читает только TLS ClientHello, выбирает route по SNI и отправляет исходные байты upstream. Сертификаты backend используются напрямую: Raddy их не расшифровывает и не подменяет.
- SNI: точное имя, `*.example.com` на один DNS-label, `"*"` для fallback. Без SNI и без fallback соединение закрывается.
- `connect_timeout_secs`: подключение к upstream, по умолчанию `10`.
- `idle_timeout_secs`: отсутствие данных в любую сторону, по умолчанию `300`.
- `handshake_timeout_secs`: чтение ClientHello, по умолчанию `10`.
- `max_handshake_bytes`: максимум данных ClientHello, по умолчанию `16384`.

SNI — не аутентификация: клиент может указать чужое имя. Для ограничения доступа используйте firewall, mTLS на backend или другую защиту приложения. Plain HTTP не делит порт со stream или HTTPS.

### Таймауты HTTP reverse proxy по маршрутам

```caddyfile
reverse_proxy http://127.0.0.1:10001 {
    connect_timeout 10s
    response_header_timeout 30s
    stream_idle_timeout 5m
}
```

Опции Raddy принимают положительные интервалы в целых секундах. `connect_timeout` задаёт лимит TCP-подключения (по умолчанию 10 с, не таймаут TLS). `response_header_timeout` ограничивает ожидание заголовков upstream с учётом повторов; продвижение upload продлевает ожидание. `stream_idle_timeout` ограничивает паузу при ожидании тела ответа после заголовков; активная отправка тела **того же HTTP-запроса** также продлевает ожидание. Активность разных запросов XHTTP не суммируется; к WebSocket после Upgrade этот таймер не применяется. Без переопределений действует прежний глобальный `request_timeout`. JSON: `connect_timeout_secs`, `response_header_timeout_secs`, `stream_idle_timeout_secs` в `proxy`. Доступно с v0.4.1.

## PROXY protocol

В сборках новее `v0.2.0` поддерживается отправка PROXY v1/v2 к backend. Включайте её только на тех маршрутах, где backend ожидает заголовок перед первым байтом своего протокола:

```caddyfile
tls://pass.example.com:443 {
    proxy 127.0.0.1:10002 {
        proxy_protocol v2
    }
}

*.example.com {
    handle /tunnel/* {
        reverse_proxy h2c://127.0.0.1:10003 {
            proxy_protocol v2
        }
    }
}
```

В `tcp://` и `layer4` опция задаётся внутри `proxy` так же, как в `tls://`. Для WebSocket и XHTTP она задаётся внутри `reverse_proxy http://…`; для HTTPS-upstream заголовок идёт до TLS-рукопожатия. Для `reverse_proxy` с этой опцией соединения с backend не переиспользуются между запросами: заголовок PROXY относится ко всему TCP-соединению. Активные health checks на таком маршруте тоже отправляют заголовок, но без клиентского адреса.

Приём заголовка включается отдельно для порта и применяется ко всем режимам на этом порту, до HTTP, TLS и выбора SNI:

```caddyfile
{
    proxy_protocol_accept 443 192.0.2.10 2001:db8::10/128
}
```

На таком порту заголовок обязателен и принимается только от перечисленных адресов/CIDR; без заголовка или с недоверенного IP соединение закрывается. Не добавляйте `proxy_protocol_accept`, если клиенты подключаются напрямую. `X-Forwarded-For` использует принятый исходный IP вместо адреса балансировщика. Поддерживаются IPv4/IPv6 поверх TCP, `UNKNOWN`/`LOCAL` сохраняют адрес непосредственного соединения, TLV не пересылаются. В JSON приём задаётся в `proxy_protocol_accept` (словарь портов и доверенных адресов), отправка — `"proxy_protocol": "v1"` или `"v2"` в stream route или в HTTP `proxy`.

На слушателе с завершением HTTPS закрытие соединения до конца рукопожатия, неверный тип TLS-записи и таймаут рукопожатия пишутся по отдельности на уровне `debug`. На `info` раз в минуту, а также при смене конфигурации, появляется `TLS handshake summary`, если счётчики ненулевые. Сводка не содержит IP клиентов или SNI. Другие ошибки рукопожатия и ошибки расшифровки уже установленных соединений остаются на уровне `warn`.

## Проверка

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --release --locked
python3 tests/network.py target/release/raddy
python3 -B tests/http_proxy.py target/release/raddy
# При наличии Caddy 2.10.2 в PATH:
python3 tests/caddy_parity.py target/release/raddy
```

`RADDY_CLOUDFLARE_API_BASE` переопределяет URL Cloudflare API для локального mock. Файлы `raddy-data` и `raddy.json` не нужно коммитить.

Перед публичным запуском проверьте `raddy --config Raddyfile validate`, затем выпуск сертификата на ACME staging с реальной тестовой зоной. Проверка конфига подготавливает обработчики, проверяет корни файловых маршрутов и читает заданные PEM, но не занимает порты и не обращается к CA. Автоматические сертификаты сохраняются с ключом в `bundle.pem` с правами `0600`, отдельно для каждого URL ACME CA. Старые пакеты без привязки к CA не используются автоматически — первый запуск после обновления может потребовать нового выпуска. Сохраняйте копию `data_dir` для отката. Запланированное удаление TXT записывается в журнал до изменения DNS; незавершённая очистка повторяется при запуске и при плановом продлении, если Cloudflare настроен.

Начиная с v0.5.0-rc.1 можно завершать HTTPS на нескольких портах в одном процессе. Например, `*.example.com` и `https://*.example.com:9443` с `bind 127.0.0.1` во втором блоке используют независимые маршруты и сертификаты; `tls://pass.example.com:443` влияет только на порт 443. В JSON адрес задаётся полем `listen` сайта HTTPS (`IP:порт`, по умолчанию `https_addr`). На одном порту разрешён один адрес привязки; одинаковый шаблон имени на разных портах допустим. При нескольких портах автоматические HTTP-редиректы используют только сайты основного HTTPS-слушателя и не перенаправляют на дополнительный внутренний порт. Для обычного HTTP сохраняется один слушатель. В Caddyfile `root` только задаёт каталог, для раздачи нужен `file_server`. В прежнем JSON-формате поле сайта `root` по-прежнему включает раздачу.

Для HTTP reverse proxy `X-Forwarded-For` задаётся адресом непосредственного клиента: Raddy не доверяет цепочке из входящего заголовка. Если Raddy стоит за другим прокси, этот адрес будет адресом того прокси. Запускайте Raddy под выделенной учётной записью и не открывайте наружу TCP listener для внутренних сервисов.

На Unix `SIGUSR1` перечитывает исходный конфиг (`docker compose kill -s SIGUSR1 raddy` для Docker Compose). При ошибке конфига, сертификата или привязки нового порта старый конфиг остаётся активным. Текущие HTTP-запросы завершаются на старом конфиге; WebSocket и TCP/TLS passthrough сохраняют уже открытые туннели. `SIGTERM`/`SIGINT` прекращают принимать соединения и дают активному трафику до 30 секунд на завершение. Срок можно задать через `run --grace-period-secs`; настройте и таймаут остановки контейнера (`stop_grace_period`), иначе Docker может принудительно завершить процесс раньше.

## Границы совместимости

Caddyfile-поддержка ограничена существующим движком Raddy. Для сайтов поддерживаются адреса `http://`, `https://`, `host[:port]`, `root`, `file_server` с `root`/`index`, `reverse_proxy` и `upstream`, `respond`, `header` (только установка значения), `tls` с PEM, email, `ca` и `dns cloudflare`. Глобальные опции: `email`, `acme_ca`, `data_dir`, `default_bind`, `http_port`, `https_port`, `http_addr`, `https_addr`, `auto_https off|disable_redirects`, `cloudflare`, `dns cloudflare`, `layer4` и настройки таймаутов/кэша из JSON.

```caddyfile
:80 {
    respond /healthz "ok" 200
    reverse_proxy app:8080
}
```

`respond` принимает тело, конечный статус `200`–`599` или тело и статус. Можно указать точный путь, префикс (`/api/*`) или `*` для всех путей. Путь проверяется без учёта регистра и query; более длинные совпадения идут раньше, точное совпадение выигрывает у префикса той же длины. Совпавший `respond` выполняется до `reverse_proxy` и `file_server`, а вариант без пути перехватывает весь сайт. Для блока `respond` доступны `body` и `close` (`close` применяется только для HTTP/1.x). В теле можно использовать перечисленные ниже подстановки запроса и захваты. Эквивалент в JSON: `"responses": [{"path":"/healthz","status":200,"body":"ok"}]` внутри сайта.

У `reverse_proxy` есть `to` (или `upstream`), `lb_policy round_robin|first`, `health_uri`, `health_interval` и `health_timeout`. Активная проверка ожидает `200`; неисправный backend исключается до успешной проверки. `lb_retries` ограничивает число дополнительных попыток при ошибке транспорта, только для `GET`/`HEAD` без тела и без Upgrade; запрос не посылается повторно на тот же backend. `header_up` и `header_down` принимают литеральные значения, префикс `+` для добавления или `-` для удаления. По умолчанию `https://` upstream получает свой `Host`, а `X-Forwarded-Host` содержит исходное имя клиента; `header_up Host` позволяет явно переопределить значение.

Для именованного адреса без схемы, например `app.example.com:8443`, используется HTTPS, кроме настроенного HTTP-порта. Для HTTP на нестандартном порту явно укажите `http://`. Точное имя имеет приоритет перед `*.example.com` (ровно одна метка) и сайтом без имени.

В `layer4` используется синтаксис caddy-l4: `@name tls [sni names...]`, `route @name { proxy ... }`, `upstream` и `lb_policy round_robin`. Наличие TLS matcher включает passthrough; не указывайте обработчик `tls` внутри route — он означает TLS termination и не поддерживается. Для SNI fallback используйте отдельный `@name tls` без SNI. Для listener доступны `connect_timeout`, `idle_timeout`, `handshake_timeout`, `max_handshake_bytes`. Полный пример: `Raddyfile`.

HTTP-маршруты позволяют разделить приложение и статику на одном домене:

```caddyfile
http://localhost:8080 {
    root * /srv/site

    handle /api/* {
        reverse_proxy 127.0.0.1:9001
    }

    handle_path /ws/* {
        reverse_proxy 127.0.0.1:9002
    }

    handle /example.Service/* {
        reverse_proxy h2c://127.0.0.1:9003
    }

    handle {
        try_files {path} /index.html
        file_server
    }
}
```

`handle` сохраняет путь, `handle_path` убирает указанный префикс. Из соседних `handle` выбирается первый совпавший блок; блок без условия идёт последним вне `route`. `route` выполняет директивы в порядке записи. Поддерживаются точные пути, префиксы, шаблоны вроде `/items/*/info` и именованные матчеры `@name` с `path`, `method`, `query`, `header`, `path_regexp` и `header_regexp`. Шаблоны путей поддерживают явные percent-последовательности, например `%2F`, и `%*` для сопоставления с кодированным сегментом. В `header` доступны точное значение, префикс/суффикс/подстрока через `*`, наличие и `!Field` для отсутствия. Матчеры можно объявлять внутри блоков, но нельзя переопределять унаследованное имя. Условия разных типов объединяются через И.

В маршрутах `header` поддерживает установку, добавление (`+`), удаление по имени или шаблону (`-`), значение по умолчанию (`?`), отложенные операции (`>` и `defer`), замену по regexp и блок `match` по статусу или заголовкам ответа. Заголовки, управляющие HTTP-фреймингом и WebSocket Upgrade, защищены. `rewrite` и `respond` поддерживают `{path}`, `{query}`, `{uri}` и захваты `{re.name.group}` / `{re.1}`. `try_files` проверяет точные имена и glob без следования по символическим ссылкам; поддерживаются политики `first_exist`, `first_exist_fallback`, `smallest_size`, `largest_size`, `most_recently_modified` и конечный `=4xx`/`=5xx` с `first_exist`. `handle_errors` может обрабатывать код (`404`) или класс (`5xx`): он вызывается при `error`, отсутствии файла или транспортном сбое прокси, но не для намеренных ответов `respond 404` и не для ответа backend со статусом `4xx`/`5xx`. В `respond` внутри обработчика ошибок доступны `{err.status_code}`, `{err.status_text}` и `{err.message}`.

Для CEL поддерживаются `` @name expression `...` `` и краткая форма `` @name `...` ``, базовые подстановки запроса и захватов, а из функций Caddy — `method(...)` и `path(...)`. Не все подстановки, функции и расширения CEL из Caddy доступны. Regexp использует Rust `regex`; общие шаблоны работают, но полной эквивалентности Go RE2 нет. Сайты с обычным `file_server` сохраняют быстрый путь `sendfile` для HTTP/1.x; статика внутри маршрутов отдаётся через общий HTTP-обработчик.

`import` подключает файл или glob относительно файла, в котором записана директива. Внутри сайта можно подключать именованные snippets `(name) { ... }`, объявленные ранее. Аргументы доступны как `{args[0]}`, списки — отдельным токеном `{args[:]}` или `{args[1:]}`. `{$VAR:default}` подставляется до разбора конфига; `{env.NAME}` остаётся доступным. При `SIGUSR1` перечитываются и подключённые файлы. Рекурсивные импорты отклоняются; `import` с блоком и glob `**` пока не поддерживаются.

Это не бинарная замена `caddy`: нет admin API, Caddy plugins и полной поддержки матчеров и директив Caddy. `file_server browse`, TLS internal/on-demand, HTTP/3, ACME HTTP-01/TLS-ALPN-01, UDP не реализован. Для автоматического выпуска сертификатов используется DNS-01 Cloudflare.

`file_server` возвращает `ETag`, `Last-Modified` и `Accept-Ranges: bytes`. Поддерживаются условные `GET`/`HEAD`, один диапазон в `GET`, `If-Range`, `206` и `416`. Запрос с несколькими диапазонами получает полный ответ. Запросы с одним диапазоном используют тот же обработчик, что и полная отдача. На быстром пути HTTP/1.x большие файлы передаются через `sendfile` и целиком, и по диапазону.

`reverse_proxy` поддерживает WebSocket Upgrade по HTTP/1.1 без дополнительных директив. Например, для `wss://` с завершением TLS на Raddy укажите `reverse_proxy http://127.0.0.1:10000` и настройте на этом порту WebSocket-бэкенд без TLS. Raddy сохраняет путь запроса. WebSocket поверх HTTP/2 (`CONNECT` по RFC 8441) не поддерживается.

Для gRPC с завершением TLS на Raddy используйте `reverse_proxy h2c://127.0.0.1:10000`. Клиент подключается к Raddy по HTTP/2 поверх TLS, а Raddy направляет запрос на HTTP/2-бэкенд без TLS, сразу начиная HTTP/2-соединение (prior knowledge). gRPC-сервис, путь и трейлеры ответа сохраняются. Обычный `http://` upstream по-прежнему использует HTTP/1.1; для WebSocket Upgrade указывайте его, а не `h2c://`.
