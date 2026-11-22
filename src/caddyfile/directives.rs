use anyhow::{Result, bail};

use super::lexer::Token;

#[derive(Clone, Debug)]
pub struct Directive {
    pub name: Token,
    pub args: Vec<Token>,
    pub children: Vec<Directive>,
    pub has_block: bool,
}

pub fn parse(tokens: &[Token]) -> Result<Vec<Directive>> {
    let mut cursor = 0;
    parse_directives(tokens, &mut cursor, 0)
}

fn parse_directives(tokens: &[Token], cursor: &mut usize, depth: usize) -> Result<Vec<Directive>> {
    if depth > 48 {
        bail!("Caddyfile nesting exceeds 48 blocks");
    }
    let mut directives = Vec::new();
    while *cursor < tokens.len() {
        let mut name = tokens[*cursor].clone();
        *cursor += 1;
        if name.structural {
            if name.text == "}" {
                if depth > 0 {
                    return Ok(directives);
                }
                return Err(name.error("unexpected closing brace"));
            }
            name.text.clear();
            directives.push(Directive {
                name,
                args: Vec::new(),
                children: parse_directives(tokens, cursor, depth + 1)?,
                has_block: true,
            });
            continue;
        }
        let mut directive = Directive {
            name,
            args: Vec::new(),
            children: Vec::new(),
            has_block: false,
        };
        while let Some(token) = tokens.get(*cursor) {
            if token.structural {
                if token.text == "{" {
                    *cursor += 1;
                    directive.children = parse_directives(tokens, cursor, depth + 1)?;
                    directive.has_block = true;
                }
                break;
            }
            if token.new_line || fixed_argument_count(&directive) == Some(directive.args.len()) {
                break;
            }
            directive.args.push(token.clone());
            *cursor += 1;
        }
        directives.push(directive);
    }
    if depth > 0 {
        bail!("unclosed block in Caddyfile");
    }
    Ok(directives)
}

/// Число аргументов, после которого директива заканчивается.
/// Позволяет писать директивы в одну строку: `root * ./public`.
fn fixed_argument_count(directive: &Directive) -> Option<usize> {
    match directive.name.text.as_str() {
        "tls" => match directive.args.first().map(|token| token.text.as_str()) {
            Some("off" | "force_automate" | "internal") => Some(1),
            Some(value) if value.contains('@') => Some(1),
            Some(_) => Some(2),
            None => None,
        },
        "root" if directive.args.first().map(|token| token.text.as_str()) == Some("*") => Some(2),
        "root" => Some(1),
        "email"
        | "acme_ca"
        | "data_dir"
        | "default_bind"
        | "http_port"
        | "https_port"
        | "http_addr"
        | "https_addr"
        | "auto_https"
        | "request_timeout"
        | "max_connections"
        | "max_header_size"
        | "static_cache_entries"
        | "static_cache_ttl"
        | "stream_connect_timeout"
        | "stream_idle_timeout"
        | "stream_handshake_timeout"
        | "stream_max_handshake_bytes"
        | "connect_timeout"
        | "response_header_timeout"
        | "idle_timeout"
        | "handshake_timeout"
        | "max_handshake_bytes"
        | "api_token"
        | "zone_token"
        | "api_base"
        | "timeout"
        | "retries"
        | "bind"
        | "ca"
        | "dial"
        | "proxy_protocol"
        | "half_close_timeout" => Some(1),
        "protocols" if directive.args.len() == 2 => Some(2),
        _ => None,
    }
}
