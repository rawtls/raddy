use std::{path::PathBuf, time::Duration};

use super::lexer::tokenize;
use super::{builder::parse_duration, parse};
use crate::config::StreamMode;

#[test]
fn expands_caddyfile_environment_before_lexing() {
    use super::imports::expand_env;

    let expanded = expand_env(
        "{$PORT:8080} {$UNSET} \"{$BODY:fallback text}\" {$EMPTY:never}",
        |name| match name {
            "PORT" => Some("9000".to_owned()),
            "EMPTY" => Some(String::new()),
            _ => None,
        },
    )
    .unwrap();
    assert_eq!(expanded, "9000  \"fallback text\" ");
    let config = parse(":8080 {\nrespond \"{$RADDY_TEST_UNSET_F32ED2:from default}\"\n}").unwrap();
    assert_eq!(config.sites[0].responses[0].body, "from default");
    assert!(expand_env("{$BAD-NAME}", |_| None).is_err());
}

#[test]
fn snippets_expand_positional_arguments_and_slices() {
    let config = parse(
        r#"
(snippet) {
    reverse_proxy {args[1:]}
    respond /probe "prefix {args[0]}" 201
}
:8080 {
    import snippet "two words" localhost:9001 localhost:9002
}
"#,
    )
    .unwrap();
    let site = &config.sites[0];
    assert_eq!(
        site.upstreams,
        ["http://localhost:9001", "http://localhost:9002"]
    );
    assert_eq!(site.responses[0].body, "prefix two words");
    assert_eq!(site.responses[0].status, 201);
    assert!(
        parse("(loop) {\nimport loop\n}\n:8080 {\nimport loop\n}")
            .unwrap_err()
            .chain()
            .any(|error| error.to_string().contains("recursive import"))
    );
    assert!(parse("(arg) {\nrespond \"{args[:]}\"\n}\n:8080 {\nimport arg one two\n}").is_err());
}

#[test]
fn file_imports_resolve_relative_paths_and_ignore_hidden_glob_entries() {
    let work = std::env::temp_dir().join(format!("raddy-caddyfile-imports-{}", std::process::id()));
    std::fs::create_dir_all(work.join("parts/sites")).unwrap();
    let result = (|| -> anyhow::Result<()> {
        std::fs::write(
            work.join("Caddyfile"),
            "import parts/common outer\nimport parts/sites/*\nimport parts/missing/*.caddy\n",
        )?;
        std::fs::write(
            work.join("parts/common"),
            "(health) {\nimport routes {args[:]}\n}\n",
        )?;
        std::fs::write(work.join("parts/sites/.hidden"), "{\n")?;
        std::fs::write(
            work.join("parts/sites/one"),
            ":8080 {\nimport health /health ok\n}\n",
        )?;
        std::fs::write(work.join("parts/routes"), "respond {args[0]} {args[1]}\n")?;
        let config = super::parse_file(&work.join("Caddyfile"))?;
        assert_eq!(
            config.sites[0].responses[0].path.as_deref(),
            Some("/health")
        );
        assert_eq!(config.sites[0].responses[0].body, "ok");
        std::fs::write(work.join("parts/routes"), "import routes\n")?;
        let error = super::parse_file(&work.join("Caddyfile")).unwrap_err();
        assert!(error.chain().any(|cause| {
            let message = cause.to_string();
            message.contains("recursive import") && message.contains("parts/routes:1:")
        }));
        std::fs::write(work.join("Caddyfile"), "import missing\n")?;
        let error = super::parse_file(&work.join("Caddyfile")).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        Ok(())
    })();
    std::fs::remove_dir_all(work).unwrap();
    result.unwrap();
}

const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";

#[test]
fn parses_cloudflare_site_and_static_files() {
    let config = parse(&format!(
        r#"
            {{
                email admin@example.com
                default_bind 127.0.0.1
                https_port 8443
            }}
            example.com, www.example.com {{
                root * "./public files"
                file_server {{
                    index home.html index.html # comment
                }}
                header {{
                    Strict-Transport-Security "max-age=31536000; includeSubDomains"
                }}
                tls {{
                    dns cloudflare {{
                        api_token {TOKEN}
                        zone_token {TOKEN}
                    }}
                }}
            }}
            "#
    ))
    .unwrap();
    assert_eq!(config.email.as_deref(), Some("admin@example.com"));
    assert_eq!(config.https_addr.to_string(), "127.0.0.1:8443");
    assert_eq!(config.sites.len(), 1);
    let site = &config.sites[0];
    assert_eq!(site.hosts, ["example.com", "www.example.com"]);
    assert_eq!(
        site.root.as_deref(),
        Some(PathBuf::from("./public files").as_path())
    );
    assert_eq!(site.index, ["home.html", "index.html"]);
    assert_eq!(
        site.response_headers["Strict-Transport-Security"],
        "max-age=31536000; includeSubDomains"
    );
    assert_eq!(config.cloudflare.api_token, TOKEN);
    assert_eq!(config.cloudflare.zone_token.as_deref(), Some(TOKEN));
}

#[test]
fn parses_http_reverse_proxy_and_port() {
    let config = parse(
        r#"
            http://localhost:8080 {
                reverse_proxy localhost:9000 {
                    upstream https://127.0.0.1:9443
                    lb_policy round_robin
                }
            }
            "#,
    )
    .unwrap();
    assert_eq!(config.http_addr.to_string(), "0.0.0.0:8080");
    assert!(!config.sites[0].tls);
    assert_eq!(
        config.sites[0].upstreams,
        ["http://localhost:9000", "https://127.0.0.1:9443"]
    );
}

#[test]
fn compiles_http_matchers_and_preserves_explicit_route_order() {
    use crate::routes::{HttpAction, HttpRoute};

    let config = parse(
        r#":8080 {
            root * ./public
            @api {
                path /api/* /v2/*
                method GET POST
                header X-API v2
            }
            handle {
                try_files {path} index.html =404
                file_server
            }
            handle @api {
                route {
                    rewrite /backend?{query}
                    reverse_proxy localhost:9001
                    respond "unreachable"
                }
            }
            handle_path /assets/* {
                file_server {
                    root ./assets
                }
            }
        }"#,
    )
    .unwrap();
    let routes = &config.sites[0].routes;
    let HttpAction::Handle { routes: api, .. } = &routes[0].action else {
        panic!()
    };
    assert_eq!(routes[0].matcher.paths, ["/api/*", "/v2/*"]);
    assert_eq!(routes[0].matcher.methods, ["GET", "POST"]);
    assert_eq!(routes[0].matcher.headers["x-api"], ["v2"]);
    let HttpAction::Route { routes: api } = &api[0].action else {
        panic!()
    };
    assert!(matches!(&api[0].action, HttpAction::Rewrite { to } if to == "/backend?{query}"));
    assert!(matches!(&api[1].action, HttpAction::ReverseProxy { .. }));
    assert!(matches!(&api[2].action, HttpAction::Respond { .. }));
    assert!(
        matches!(&routes[1].action, HttpAction::Handle { strip_prefix: Some(prefix), .. } if prefix == "/assets")
    );
    let HttpAction::Handle {
        routes: fallback, ..
    } = &routes[2].action
    else {
        panic!()
    };
    assert!(
        matches!(&fallback[0].action, HttpAction::TryFiles { root, paths, status: Some(404), .. } if root == std::path::Path::new("./public") && paths == &["{path}", "index.html"])
    );
    let json = serde_json::to_string(&config).unwrap();
    let decoded: crate::config::Config = serde_json::from_str(&json).unwrap();
    decoded.validate().unwrap();
    let routes: Vec<HttpRoute> = decoded.sites.into_iter().next().unwrap().routes;
    assert_eq!(routes.len(), 3);
}

#[test]
fn parses_quoted_cel_matchers_and_rejects_invalid_expressions() {
    let config = parse(
        r#"
:8080 {
    @check `{method} == "POST"`
    @api expression `method("get", "HEAD") && path("/api/*")`
    handle @check {
        respond ok
    }
    respond @api api
}
"#,
    )
    .unwrap();
    assert_eq!(
        config.sites[0].routes[0].matcher.expression.as_deref(),
        Some("{method} == \"POST\"")
    );
    assert!(parse(":8080 {\n@bad `unknown == 2`\nrespond @bad ok\n}").is_err());
    assert!(parse(":8080 {\n@bad `1`\nrespond @bad ok\n}").is_err());
    assert!(parse(":8080 {\n@bad `{path} &&`\nrespond @bad ok\n}").is_err());
}

#[test]
fn parses_deferred_response_header_operations() {
    use crate::routes::HttpAction;

    let config = parse(
        r#"
:8080 {
    header /example {
        defer
        ?X-Mode default
        -X-Temp*
        >X-Result `^id-(\d+)$` "${1}"
        match {
            status 2xx
            header Content-Type text/*
        }
    }
    respond ok
}
"#,
    )
    .unwrap();
    let HttpAction::Header {
        operations,
        defer,
        condition,
    } = &config.sites[0].routes[0].action
    else {
        panic!()
    };
    assert!(*defer);
    assert_eq!(operations[0].name, "?X-Mode");
    assert_eq!(operations[1].name, "-X-Temp*");
    assert_eq!(operations[2].replacement.as_deref(), Some("${1}"));
    assert_eq!(condition.as_ref().unwrap().statuses, [2]);
    assert!(parse(":8080 {\nheader X-Result `[invalid` value\nrespond ok\n}").is_err());
}

#[test]
fn parses_named_regexp_and_escaped_path_matchers() {
    let config = parse(
        r#"
:8080 {
    @match {
        path_regexp `^/items/(?P<id>\d+)$`
        header_regexp agent X-Mode `^user-(\w+)$`
    }
    handle @match {
        rewrite /item/{re.match.id}
        respond "{re.agent.1}"
    }
    respond /file%2Fname escaped
    respond /bands/%*/* raw
}
"#,
    )
    .unwrap();
    let matcher = &config.sites[0].routes[0].matcher;
    assert_eq!(matcher.path_regexp.as_ref().unwrap().name, "match");
    assert_eq!(matcher.header_regexp["x-mode"].name, "agent");
    assert!(parse(":8080 {\n@bad path_regexp `[invalid`\nrespond @bad ok\n}").is_err());
    assert!(parse(":8080 {\n@bad path /invalid%\nrespond @bad ok\n}").is_err());
    assert!(
        parse(":8080 {\n@bad {\npath_regexp /one\npath_regexp /two\n}\nrespond @bad ok\n}")
            .is_err()
    );
}

#[test]
fn parses_query_globs_response_headers_and_error_routes() {
    use crate::routes::HttpAction;

    let config = parse(
        r#"
:8080 {
    @api query mode=fast mode=slow key=*
    handle /items/*/info {
        @missing header !X-Mode
        route {
            header X-Test value
            header @api +X-Test second
            respond @missing ok
            error "bad mode" 418
        }
    }
    handle_errors 4xx {
        respond "failed: {err.status_code}"
    }
}
"#,
    )
    .unwrap();
    let site = &config.sites[0];
    assert!(site.error_routes[0].matches(418));
    assert!(!site.error_routes[0].matches(503));
    let HttpAction::Handle { routes, .. } = &site.routes[0].action else {
        panic!()
    };
    let HttpAction::Route { routes } = &routes[0].action else {
        panic!()
    };
    assert_eq!(
        routes[1].matcher.query.as_ref().unwrap()["mode"],
        ["fast", "slow"]
    );
    assert!(routes[2].matcher.headers["x-mode"].is_empty());
    assert!(matches!(
        routes[3].action,
        HttpAction::Error { status: 418, .. }
    ));
    assert!(
        parse(":8080 {\n@same method GET\nhandle {\n@same method POST\nrespond @same ok\n}\n}")
            .is_err()
    );
}

#[test]
fn rejects_unsupported_or_ambiguous_http_routes() {
    for rule in [
        "reverse_proxy @missing localhost:9001",
        "handle_path @api { respond no }",
        "route /ok",
        "rewrite https://example.com/",
        "rewrite /has/{unknown}",
        "try_files /index.* { policy unknown }",
        "@bad header !X-Test value",
        "@bad path /item/[",
    ] {
        assert!(parse(&format!(":8080 {{\n {rule}\n}}")).is_err(), "{rule}");
    }
    assert!(
        parse(&format!(
            ":8080 {{ {}respond ok{} }}",
            "route { ".repeat(64),
            " }".repeat(64)
        ))
        .is_err()
    );
}

#[test]
fn proxy_timeouts_are_validated_and_round_trip_through_json() {
    let config = parse(":8080 { reverse_proxy localhost:9000 { connect_timeout 3s response_header_timeout 4s stream_idle_timeout 2m } }").unwrap();
    let json = serde_json::to_string(&config).unwrap();
    let config: crate::config::Config = serde_json::from_str(&json).unwrap();
    config.validate().unwrap();
    let proxy = &config.sites[0].proxy;
    assert_eq!(
        (
            proxy.connect_timeout_secs,
            proxy.response_header_timeout_secs,
            proxy.stream_idle_timeout_secs
        ),
        (Some(3), Some(4), Some(120))
    );
    for setting in [
        "connect_timeout 0",
        "response_header_timeout 0",
        "stream_idle_timeout 0",
        "stream_idle_timeout 1s stream_idle_timeout 2s",
    ] {
        assert!(
            parse(&format!(
                ":8080 {{ reverse_proxy localhost:9000 {{ {setting} }} }}"
            ))
            .is_err()
        );
    }
}

#[test]
fn parses_proxy_health_retries_and_literal_header_operations() {
    let config = parse(
        r#":8080 {
            reverse_proxy * {
                to localhost:9001 localhost:9002
                lb_policy first
                lb_retries 1
                health_uri /ready?q=1
                health_interval 5s
                health_timeout 2s
                header_up +X-Example value
                header_down -X-Internal
            }
        }"#,
    )
    .unwrap();
    let site = &config.sites[0];
    assert_eq!(site.upstreams.len(), 2);
    assert!(matches!(
        site.proxy.lb_policy,
        crate::config::ProxyPolicy::First
    ));
    assert_eq!(site.proxy.lb_retries, 1);
    assert_eq!(site.proxy.health_uri.as_deref(), Some("/ready?q=1"));
    assert_eq!(site.proxy.health_interval_secs, Some(5));
    assert_eq!(site.proxy.health_timeout_secs, Some(2));
    assert_eq!(site.proxy.header_up[0].name, "+X-Example");
    assert_eq!(site.proxy.header_down[0].value, None);
    assert!(parse(":80 { reverse_proxy localhost:9000 { header_up Content-Length 1 } }").is_err());
    assert!(parse(":80 { reverse_proxy localhost:9000 { health_interval 1s } }").is_err());
}

#[test]
fn infers_https_from_named_addresses_except_on_the_configured_http_port() {
    let config = parse("example.com:8443 { tls cert.pem key.pem }").unwrap();
    assert!(config.sites[0].tls);
    assert_eq!(config.https_addr.port(), 8443);
    let config = parse("{ http_port 8080 } example.com:8080 { respond ok }").unwrap();
    assert!(!config.sites[0].tls);
    assert_eq!(config.http_addr.port(), 8080);
    let config = parse(":8443 { respond ok }").unwrap();
    assert!(!config.sites[0].tls);
    assert!(parse("http://example.com:443 { respond ok }").is_err());
    assert!(parse("https://example.com:80 { tls cert.pem key.pem }").is_err());
}

#[test]
fn parses_respond_body_status_and_matchers() {
    let config = parse(
        r#"
        :8080 {
            respond "default"
            respond /healthz "ok" 201
            respond /empty 204
            respond /prefix/* 202 {
                body `line one
line two`
                close
            }
            respond /multiline `one
two` 203
            respond /brace "{" 400
            respond /literal "503" 200
            respond * 404
        }
        "#,
    )
    .unwrap();
    let rules = &config.sites[0].responses;
    assert_eq!(rules[0].status, 200);
    assert_eq!(rules[0].body, "default");
    assert_eq!(rules[1].path.as_deref(), Some("/healthz"));
    assert_eq!(rules[1].status, 201);
    assert_eq!(rules[1].body, "ok");
    assert_eq!(rules[2].status, 204);
    assert_eq!(rules[2].body, "");
    assert_eq!(rules[3].path.as_deref(), Some("/prefix/*"));
    assert!(rules[3].close);
    assert_eq!(rules[3].body, "line one\nline two");
    assert_eq!(rules[4].status, 203);
    assert_eq!(rules[4].body, "one\ntwo");
    assert_eq!(rules[5].body, "{");
    assert_eq!(rules[6].body, "503");
    assert_eq!(rules[7].path, None);
}

#[test]
fn rejects_unsupported_or_invalid_respond_arguments() {
    for instruction in [
        "respond",
        "respond /healthz",
        "respond @healthz ok",
        "respond /api/[ ok",
        "respond /encoded%2xpath ok",
        "respond ok text",
        "respond 103",
        "respond ok 600",
        "respond a 200 { body b }",
        "respond 200 { close now }",
    ] {
        let input = format!(":8080 {{\n    {instruction}\n}}");
        assert!(
            parse(&input).unwrap_err().to_string().starts_with("2:"),
            "{input}"
        );
    }
}

#[test]
fn parses_layer4_sni_routes_and_tcp() {
    let config = parse(
        r#"
            {
                layer4 {
                    :9443 {
                        connect_timeout 2s
                        idle_timeout 1m30s
                        handshake_timeout 5
                        max_handshake_bytes 8192
                        @app tls sni app.example.com api.example.com
                        route @app {
                            proxy {
                                lb_policy round_robin
                                upstream 10.0.0.10:443
                                upstream 10.0.0.11:443
                            }
                        }
                        @wildcard tls {
                            sni *.internal.example.com
                        }
                        route @wildcard { proxy tcp/10.0.1.10:443 }
                        @fallback tls
                        route @fallback { proxy 10.0.2.10:443 }
                    }
                    127.0.0.1:5432 {
                        route { proxy 10.0.0.20:5432 }
                    }
                }
            }
            "#,
    )
    .unwrap();
    assert_eq!(config.sites.len(), 0);
    assert_eq!(config.streams.len(), 2);
    let tls = &config.streams[0];
    assert_eq!(tls.listen.to_string(), "0.0.0.0:9443");
    assert_eq!(tls.mode, StreamMode::TlsPassthrough);
    assert_eq!(tls.connect_timeout_secs, 2);
    assert_eq!(tls.idle_timeout_secs, 90);
    assert_eq!(tls.max_handshake_bytes, 8192);
    assert_eq!(tls.routes.len(), 4, "{:#?}", tls.routes);
    assert_eq!(tls.routes[0].sni.as_deref(), Some("app.example.com"));
    assert_eq!(tls.routes[0].upstreams, ["10.0.0.10:443", "10.0.0.11:443"]);
    assert_eq!(tls.routes[2].sni.as_deref(), Some("*.internal.example.com"));
    assert_eq!(tls.routes[3].sni.as_deref(), Some("*"));
    assert_eq!(config.streams[1].mode, StreamMode::Tcp);
    assert_eq!(config.streams[1].routes[0].sni, None);
}

#[test]
fn short_stream_addresses_merge_tls_routes_and_keep_tcp_separate() {
    let config = parse(
        r#"
            tls://app.example.com:9443 {
                bind 127.0.0.1
                connect_timeout 2s
                idle_timeout 45s
                proxy 10.0.0.10:443 10.0.0.11:443
            }
            tls://*.internal.example.com:9443 {
                bind 127.0.0.1
                proxy 10.0.1.10:443
            }
            tls://*:9443 {
                bind 127.0.0.1
                handshake_timeout 3s
                proxy 10.0.2.10:443
            }
            tcp://127.0.0.1:5432 {
                proxy 10.0.0.20:5432
            }
            "#,
    )
    .unwrap();
    assert_eq!(config.streams.len(), 2);
    let stream = &config.streams[0];
    assert_eq!(stream.listen.to_string(), "127.0.0.1:9443");
    assert_eq!(stream.mode, StreamMode::TlsPassthrough);
    assert_eq!(stream.connect_timeout_secs, 2);
    assert_eq!(stream.idle_timeout_secs, 45);
    assert_eq!(stream.handshake_timeout_secs, 3);
    assert_eq!(
        stream
            .routes
            .iter()
            .map(|route| route.sni.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["app.example.com", "*.internal.example.com", "*"]
    );
    assert_eq!(
        stream.routes[0].upstreams,
        ["10.0.0.10:443", "10.0.0.11:443"]
    );
    assert_eq!(config.streams[1].mode, StreamMode::Tcp);
    assert_eq!(config.streams[1].routes[0].sni, None);
}

#[test]
fn short_stream_addresses_reject_ambiguous_ports_and_routes() {
    let cases = [
        (
            "tls://app.example.com:9443 { proxy 127.0.0.1:4443 } tls://app.example.com:9443 { proxy 127.0.0.1:4444 }",
            "duplicate TLS SNI route",
        ),
        (
            "tcp://:5432 { proxy 127.0.0.1:5433 } tcp://:5432 { proxy 127.0.0.1:5434 }",
            "use one tcp:// block",
        ),
        (
            "tcp://:9443 { proxy 127.0.0.1:4443 } http://localhost:9443 { root . }",
            "conflicts with the HTTP listener",
        ),
        (
            "tls://app.example.com:9443 { bind 127.0.0.1 proxy 127.0.0.1:4443 } tls://api.example.com:9443 { bind 127.0.0.2 proxy 127.0.0.1:4443 }",
            "must use the same bind address",
        ),
        (
            "tls://app.example.com:9443 { connect_timeout 2s proxy 127.0.0.1:4443 } tls://api.example.com:9443 { connect_timeout 3s proxy 127.0.0.1:4443 }",
            "conflicting connect_timeout",
        ),
        (
            "tcp://example.com:5432 { proxy 127.0.0.1:5433 }",
            "must be :port or an IP:port",
        ),
    ];
    for (input, message) in cases {
        let error = parse(input).unwrap_err();
        assert!(
            error.to_string().contains(message),
            "expected {message:?}, got {error}"
        );
    }
}

#[test]
fn conflicting_sni_cannot_be_both_passthrough_and_https() {
    let error = parse("tls://app.example.com:443 { proxy 127.0.0.1:4443 } https://app.example.com { tls cert.pem key.pem root . }")
            .unwrap_err();
    assert!(error.to_string().contains("duplicate SNI pattern"));
    assert!(parse("tls://app.example.com { proxy 127.0.0.1:443 }").is_err());
    assert!(parse("tcp://:443 { tls off proxy 127.0.0.1:4443 }").is_err());
}

#[test]
fn tls_https_and_tcp_share_a_port_in_any_order() {
    let tcp = "tcp://:443 { proxy 127.0.0.1:10003 }";
    let passthrough = "tls://test.example.com:443 { proxy 127.0.0.1:10002 }";
    let https = "*.example.com { tls cert.pem key.pem respond ok }";
    for input in [
        format!("{tcp}\n{passthrough}\n{https}"),
        format!("{https}\n{passthrough}\n{tcp}"),
    ] {
        let config = parse(&input).unwrap();
        assert_eq!(config.streams.len(), 2);
        assert!(
            config
                .streams
                .iter()
                .all(|stream| stream.listen == config.https_addr)
        );
    }
    assert!(parse("tls://*.example.com:443 { proxy 127.0.0.1:10002 }\n*.EXAMPLE.com { tls cert.pem key.pem }").is_err());
}

#[test]
fn supports_custom_certificates_without_cloudflare() {
    let config = parse(
            "https://example.com:9443 { tls ./certificate.pem ./private.key reverse_proxy 127.0.0.1:9000 }",
        )
        .unwrap();
    assert_eq!(config.https_addr.port(), 9443);
    assert_eq!(
        config.sites[0].certificate_file.as_deref(),
        Some(PathBuf::from("./certificate.pem").as_path())
    );
    assert!(config.cloudflare.api_token.is_empty());
}

#[test]
fn reports_unsupported_directives_and_bad_syntax() {
    let error = parse("http://localhost { encode zstd }").unwrap_err();
    assert!(error.to_string().contains("1:20"), "{error}");
    assert!(error.to_string().contains("unsupported site directive"));
    assert!(parse("http://localhost {").is_err());
    assert!(parse("http://localhost { root \"unterminated }").is_err());
}

#[test]
fn rejects_incompatible_listener_ports_and_unknown_matchers() {
    assert!(parse("http://a.local:8080 { root . } http://b.local:8081 { root . }").is_err());
    assert!(parse("{ layer4 { :9443 { route @missing { proxy localhost:443 } } } }").is_err());
}

#[test]
fn parses_quoted_braces_and_comments() {
    let tokens = tokenize("http://localhost { header X-Test \"a {b} # c\" }").unwrap();
    assert!(tokens.iter().any(|token| token.text == "a {b} # c"));
}

#[test]
fn parses_compound_durations() {
    assert_eq!(parse_duration("2m3s").unwrap(), Duration::from_secs(123));
    assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
    assert!(parse_duration("-1").is_err());
    assert!(parse_duration("1w").is_err());
}

#[test]
fn listener_binds_are_independent_and_conflicts_are_rejected() {
    let config = parse("{ default_bind 127.0.0.1 }\nhttp://a.test { bind 127.0.0.2 respond a }\nhttps://b.test { tls cert.pem key.pem respond b }\ntcp://:9999 { proxy 127.0.0.1:9000 }").unwrap();
    assert_eq!(config.http_addr.ip().to_string(), "127.0.0.2");
    assert_eq!(config.https_addr.ip().to_string(), "127.0.0.1");
    assert_eq!(config.streams[0].listen.ip().to_string(), "127.0.0.1");
    for second in ["bind 127.0.0.1 respond b", "respond b"] {
        assert!(
            parse(&format!(
                "http://a.test {{ bind 127.0.0.2 respond a }}\nhttp://b.test {{ {second} }}"
            ))
            .is_err()
        );
        assert!(
            parse(&format!(
                "http://b.test {{ {second} }}\nhttp://a.test {{ bind 127.0.0.2 respond a }}"
            ))
            .is_err()
        );
    }
}

#[test]
fn wildcard_sites_are_scoped_to_the_https_listener_in_any_order() {
    let global = format!("{{ cloudflare {TOKEN} }}");
    let public = "*.eu2.example.test {\n handle /ws { reverse_proxy 127.0.0.1:10002 { proxy_protocol v2 } }\n handle { respond fallback }\n}";
    let local = "https://*.eu2.example.test:9443 {\n bind 127.0.0.1\n handle {\n rewrite /private/\n reverse_proxy https://origin.example.test\n }\n}";
    let pass = "tls://test.eu2.example.test:443 { proxy 127.0.0.1:10003 }";
    for blocks in [[local, public, pass], [pass, public, local]] {
        let config = parse(&format!("{global}\n{}", blocks.join("\n"))).unwrap();
        let json = serde_json::to_vec(&config).unwrap();
        let config: crate::config::Config = serde_json::from_slice(&json).unwrap();
        config.validate().unwrap();
        assert_eq!(config.https_addr.to_string(), "0.0.0.0:443");
        assert_eq!(config.https_listeners().len(), 2);
        assert!(
            config
                .https_listeners()
                .contains(&"127.0.0.1:9443".parse().unwrap())
        );
        assert_eq!(config.streams[0].listen, config.https_addr);
    }
    let collision = "tls://*.eu2.example.test:443 { proxy 127.0.0.1:10003 }";
    assert!(parse(&format!("{global}\n{local}\n{public}\n{collision}")).is_err());
    assert!(parse(&format!("{global}\n{local}\n{collision}")).is_ok());
}

#[test]
fn root_without_file_server_does_not_enable_static_files() {
    let config = parse("http://a.test { root ./public }").unwrap();
    assert!(config.sites[0].root.is_none());
    let config = parse("http://a.test { root ./public file_server }").unwrap();
    assert_eq!(config.sites[0].root, Some(PathBuf::from("./public")));
}

#[test]
fn duplicate_sites_and_late_tls_stream_conflicts_are_rejected() {
    assert!(parse("http://a.test { respond one }\nhttp://A.test. { respond two }").is_err());
    let first = "tls://a.test:9443 { proxy 127.0.0.1:9000 }";
    let second = "tls://b.test:9443 { handshake_timeout 2s proxy 127.0.0.1:9000 }";
    let third = "tls://c.test:9443 { handshake_timeout 3s proxy 127.0.0.1:9000 }";
    assert!(
        parse(&format!("{first}\n{second}\n{third}"))
            .unwrap_err()
            .to_string()
            .contains("conflicting handshake_timeout")
    );
}

#[test]
fn inline_header_and_default_port_keep_their_meaning() {
    let config = parse("http://a.test:80 {\n header X-Test hello\n root .\n}").unwrap();
    assert_eq!(config.http_addr.port(), 80);
    assert_eq!(config.sites[0].response_headers["X-Test"], "hello");
    for input in [
        "http://a.test:80 { root . }\nhttp://b.test:8181 { root . }",
        "http://b.test:8181 { root . }\nhttp://a.test:80 { root . }",
    ] {
        assert!(
            parse(input)
                .unwrap_err()
                .to_string()
                .contains("multiple HTTP ports")
        );
    }
}
