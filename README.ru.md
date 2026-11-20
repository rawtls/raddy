# Raddy

Raddy — обратный прокси и файловый сервер на Rust. Он умеет отдавать статику по HTTPS, проксировать приложение и передавать обычный TCP. На одном порту Raddy может завершать HTTPS для одного имени и пропускать TLS к другому сервису.

[English](README.md) · [Настройка](docs/CONFIGURATION.ru.md) · [Замеры](docs/BENCHMARKS.md) · [Релизы](https://github.com/rawtls/raddy/releases)

## Быстрый старт

Создайте `Raddyfile` в пустом каталоге:

```caddyfile
:8080 {
    respond "Hello from Raddy"
}
```

Запустите контейнер:

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  --mount type=bind,src="$PWD/Raddyfile",dst=/etc/raddy/Raddyfile,readonly \
  ghcr.io/rawtls/raddy:v0.3.0
```

Откройте `http://127.0.0.1:8080/`. Для этого примера не нужны домен или токен Cloudflare. Для развёртывания на Linux есть [пример Docker Compose](docs/CONFIGURATION.ru.md#docker-compose-linux-сеть-хоста) с отдельным томом для сертификатов и ротацией логов.

## Что дальше

- [Включить HTTPS через Cloudflare DNS-01](docs/CONFIGURATION.md#cloudflare-dns-01)
- [Настроить TCP и TLS passthrough](docs/CONFIGURATION.ru.md#tcp-и-tls-passthrough)
- Сравнить Raddy, Caddy, nginx, Traefik и HAProxy: [HTTP/HTTPS-прокси](docs/BENCHMARKS.proxy.md) · [TCP/TLS passthrough](docs/BENCHMARKS.layer4.md). Отдельно — [прямая раздача статики](docs/BENCHMARKS.md).

Проект развивается. Поддержка синтаксиса Caddyfile частичная: Raddy [не является полной заменой Caddy](docs/CONFIGURATION.ru.md#границы-совместимости).

[Apache-2.0](LICENSE) · [Сообщить об уязвимости](SECURITY.md)
