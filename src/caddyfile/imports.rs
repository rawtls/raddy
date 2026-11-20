use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};

use super::lexer::{Token, tokenize};

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOKENS: usize = 131_072;
const MAX_DEPTH: usize = 32;
const MAX_IMPORTS: usize = 4096;

pub(super) fn load(path: &Path) -> Result<(Vec<Token>, Vec<PathBuf>)> {
    let mut expander = Expander::default();
    let canonical = path
        .canonicalize()
        .with_context(|| format!("could not open {}", path.display()))?;
    let source = Arc::new(path.to_owned());
    let tokens = expander.read(&source)?;
    expander.files.push(canonical.clone());
    expander.active.push(Import::File(canonical));
    expander.expand(&tokens, 0, None)?;
    Ok((expander.output, expander.files))
}

pub(super) fn expand(input: &str) -> Result<Vec<Token>> {
    let mut expander = Expander::default();
    let tokens = lex(input, None)?;
    expander.expand(&tokens, 0, None)?;
    Ok(expander.output)
}

#[derive(Default)]
struct Expander {
    snippets: BTreeMap<String, Arc<[Token]>>,
    active: Vec<Import>,
    output: Vec<Token>,
    files: Vec<PathBuf>,
    bytes: usize,
    output_bytes: usize,
    imports: usize,
}

#[derive(PartialEq, Eq)]
enum Import {
    File(PathBuf),
    Snippet(String),
}

impl Expander {
    fn read(&mut self, path: &Arc<PathBuf>) -> Result<Vec<Token>> {
        let mut input = String::new();
        let mut options = File::options();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options
            .open(path.as_ref())
            .with_context(|| format!("could not open {}", path.display()))?;
        if !file.metadata()?.is_file() {
            bail!("import is not a regular file: {}", path.display());
        }
        file.take((MAX_BYTES - self.bytes + 1) as u64)
            .read_to_string(&mut input)
            .with_context(|| format!("could not read {}", path.display()))?;
        self.bytes += input.len();
        if self.bytes > MAX_BYTES {
            bail!("Caddyfile and imports exceed {MAX_BYTES} bytes");
        }
        lex(&input, Some(path.clone()))
            .with_context(|| format!("could not tokenize {}", path.display()))
    }

    fn expand(&mut self, tokens: &[Token], mut depth: usize, args: Option<&[Token]>) -> Result<()> {
        let mut i = 0;
        while let Some(token) = tokens.get(i) {
            if token.structural {
                if token.text == "{" {
                    depth += 1;
                } else {
                    depth = depth.saturating_sub(1);
                }
            } else if token.new_line && !token.quoted {
                if token.text == "import" {
                    let end = i
                        + 1
                        + tokens[i + 1..]
                            .iter()
                            .take_while(|token| !token.new_line && !token.structural)
                            .count();
                    let directive = &tokens[i + 1..end];
                    let evaluated;
                    let directive = if let Some(args) = args {
                        evaluated = substitute(directive, args)?;
                        evaluated.as_slice()
                    } else {
                        directive
                    };
                    let Some((target, arguments)) = directive.split_first() else {
                        return Err(token.error("import requires a file, glob or snippet name"));
                    };
                    if tokens.get(end).is_some_and(|token| {
                        !token.new_line && token.structural && token.text == "{"
                    }) {
                        return Err(token.error("import blocks are not supported"));
                    }
                    self.include(target, arguments, depth)?;
                    i = end;
                    continue;
                }
                if depth == 0
                    && let Some(name) = token
                        .text
                        .strip_prefix('(')
                        .and_then(|name| name.strip_suffix(')'))
                {
                    if name.is_empty()
                        || !tokens
                            .get(i + 1)
                            .is_some_and(|token| token.structural && token.text == "{")
                    {
                        return Err(token.error("snippet requires a name and a block"));
                    }
                    let start = i + 2;
                    let mut balance = 1;
                    let closing = tokens[start..]
                        .iter()
                        .position(|token| {
                            if token.structural {
                                if token.text == "{" {
                                    balance += 1;
                                } else {
                                    balance -= 1;
                                }
                            }
                            balance == 0
                        })
                        .ok_or_else(|| token.error("unclosed snippet"))?
                        + start;
                    let mut body = tokens[start..closing].to_vec();
                    if let Some(first) = body.first_mut() {
                        first.new_line = true;
                    }
                    if self.snippets.contains_key(name) {
                        return Err(token.error(format!("duplicate snippet {name:?}")));
                    }
                    self.snippets.insert(name.to_owned(), body.into());
                    i = closing + 1;
                    continue;
                }
            }
            if let Some(args) = args
                && !token.structural
                && token.text.contains("{args[")
            {
                for token in substitute(std::slice::from_ref(token), args)? {
                    self.push(token)?;
                }
            } else {
                self.push(token.clone())?;
            }
            i += 1;
        }
        Ok(())
    }

    fn push(&mut self, token: Token) -> Result<()> {
        self.output_bytes += token.text.len();
        if self.output.len() >= MAX_TOKENS || self.output_bytes > MAX_BYTES {
            return Err(token.error("expanded Caddyfile exceeds size limit"));
        }
        self.output.push(token);
        Ok(())
    }

    fn include(&mut self, token: &Token, args: &[Token], depth: usize) -> Result<()> {
        if let Some(body) = self.snippets.get(&token.text).cloned() {
            self.enter(Import::Snippet(token.text.clone()), token)?;
            self.expand(&body, depth, Some(args)).with_context(|| {
                token.error(format!("while importing snippet {:?}", token.text))
            })?;
            self.active.pop();
            return Ok(());
        }
        let Some(source) = &token.source else {
            return Err(token.error(format!(
                "cannot import file {:?} without a Caddyfile path",
                token.text
            )));
        };
        let parent = source.parent().unwrap_or_else(|| Path::new("."));
        let paths = import_paths(parent, &token.text)
            .with_context(|| token.error("could not resolve import"))?;
        for path in paths {
            let canonical = fs::canonicalize(&path).with_context(|| {
                token.error(format!("could not resolve import {}", path.display()))
            })?;
            self.files.push(canonical.clone());
            self.enter(Import::File(canonical), token)?;
            let file = self.read(&Arc::new(path))?;
            self.expand(&file, depth, Some(args))?;
            self.active.pop();
        }
        Ok(())
    }

    fn enter(&mut self, source: Import, token: &Token) -> Result<()> {
        self.imports += 1;
        if self.active.len() >= MAX_DEPTH || self.imports > MAX_IMPORTS {
            return Err(token.error("Caddyfile imports exceed recursion or count limit"));
        }
        if self.active.contains(&source) {
            return Err(token.error(format!("recursive import of {:?}", token.text)));
        }
        self.active.push(source);
        Ok(())
    }
}

fn import_paths(parent: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    if !pattern.contains(['*', '?', '[']) {
        return Ok(vec![parent.join(pattern)]);
    }
    if pattern.contains("**") {
        bail!("recursive '**' import patterns are not supported");
    }
    let path = Path::new(pattern);
    let absolute_pattern = if path.is_absolute() {
        pattern.to_owned()
    } else {
        let parent = parent.to_str().context("import path is not UTF-8")?;
        if parent.is_empty() {
            pattern.to_owned()
        } else {
            format!("{}/{pattern}", glob::Pattern::escape(parent))
        }
    };
    let exclude_hidden = path.file_name().is_some_and(|name| name == "*");
    let mut paths = Vec::new();
    for matched in glob::glob(&absolute_pattern)? {
        let matched = matched?;
        if exclude_hidden
            && matched
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b"."))
        {
            continue;
        }
        if paths.len() >= MAX_IMPORTS {
            bail!("import glob has too many matches");
        }
        paths.push(matched);
    }
    paths.sort_unstable();
    Ok(paths)
}

fn substitute(tokens: &[Token], args: &[Token]) -> Result<Vec<Token>> {
    let mut expanded = Vec::with_capacity(tokens.len());
    let mut new_line = false;
    let mut bytes = 0;
    for token in tokens {
        let starts_line = new_line || token.new_line;
        new_line = false;
        if !token.structural
            && let Some(range) = token
                .text
                .strip_prefix("{args[")
                .and_then(|text| text.strip_suffix("]}"))
            && let Some((start, end)) = range.split_once(':')
        {
            if token.quoted {
                return Err(
                    token.error("import argument slices must be unquoted standalone tokens")
                );
            }
            let index = |text: &str, default| {
                if text.is_empty() {
                    Ok(default)
                } else {
                    text.parse::<usize>()
                }
            };
            let start = index(start, 0).map_err(|_| token.error("invalid import slice start"))?;
            let end =
                index(end, args.len()).map_err(|_| token.error("invalid import slice end"))?;
            let values = args
                .get(start..end)
                .ok_or_else(|| token.error("import slice out of bounds"))?;
            new_line = starts_line && values.is_empty();
            for (i, argument) in values.iter().enumerate() {
                bytes += argument.text.len();
                if expanded.len() >= MAX_TOKENS || bytes > MAX_BYTES {
                    return Err(token.error("import has too many tokens"));
                }
                expanded.push(Token {
                    text: argument.text.clone(),
                    new_line: starts_line && i == 0,
                    quoted: argument.quoted,
                    ..token.clone()
                });
            }
            continue;
        }
        if expanded.len() >= MAX_TOKENS {
            return Err(token.error("import has too many tokens"));
        }
        let mut result = token.clone();
        result.new_line = starts_line;
        if !token.structural && token.text.contains("{args[") {
            let mut value = String::new();
            let mut rest = token.text.as_str();
            while let Some((prefix, after)) = rest.split_once("{args[") {
                value.push_str(prefix);
                let (index, next) = after
                    .split_once("]}")
                    .ok_or_else(|| token.error("unterminated import argument"))?;
                let index = index
                    .parse::<usize>()
                    .map_err(|_| token.error("expected a positional import argument index"))?;
                let argument = args
                    .get(index)
                    .ok_or_else(|| token.error(format!("import argument {index} is missing")))?;
                if value.len() + argument.text.len() > MAX_BYTES {
                    return Err(token.error("import argument exceeds size limit"));
                }
                value.push_str(&argument.text);
                rest = next;
            }
            value.push_str(rest);
            result.text = value;
        }
        bytes += result.text.len();
        if bytes > MAX_BYTES {
            return Err(token.error("expanded import exceeds size limit"));
        }
        expanded.push(result);
    }
    Ok(expanded)
}

fn lex(input: &str, source: Option<Arc<PathBuf>>) -> Result<Vec<Token>> {
    let input = expand_env(input, |name| std::env::var(name).ok())?;
    let mut tokens = tokenize(&input)?;
    if tokens.len() > MAX_TOKENS {
        bail!("Caddyfile has too many tokens");
    }
    for token in &mut tokens {
        token.source.clone_from(&source);
    }
    Ok(tokens)
}

pub(super) fn expand_env(input: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<String> {
    if input.len() > MAX_BYTES {
        bail!("Caddyfile exceeds {MAX_BYTES} bytes");
    }
    let mut expanded = String::new();
    let mut rest = input;
    while let Some((prefix, after)) = rest.split_once("{$") {
        expanded.push_str(prefix);
        let Some((expression, next)) = after.split_once('}') else {
            bail!("unterminated Caddyfile environment variable");
        };
        let (name, fallback) = expression.split_once(':').unwrap_or((expression, ""));
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!("invalid Caddyfile environment variable name {name:?}");
        }
        let value = lookup(name);
        let value = value.as_deref().unwrap_or(fallback);
        if expanded.len() + value.len() > MAX_BYTES {
            bail!("expanded Caddyfile exceeds {MAX_BYTES} bytes");
        }
        expanded.push_str(value);
        rest = next;
    }
    expanded.push_str(rest);
    if expanded.len() > MAX_BYTES {
        bail!("expanded Caddyfile exceeds {MAX_BYTES} bytes");
    }
    Ok(expanded)
}
