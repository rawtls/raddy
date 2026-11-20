//! Разбор конфигурации в формате Caddyfile/Raddyfile.
//!
//! Модуль разделён на части: лексер раскладывает текст в токены,
//! [`directives`] строит дерево директив, а [`builder`] превращает дерево
//! в готовую конфигурацию.

mod builder;
mod directives;
mod imports;
mod lexer;

use std::path::Path;

use anyhow::Result;

use crate::config::Config;

pub fn parse(input: &str) -> Result<Config> {
    let tokens = imports::expand(input)?;
    builder::build(&tokens)
}

pub(crate) fn parse_file(path: &Path) -> Result<Config> {
    let (tokens, files) = imports::load(path)?;
    let mut config = builder::build(&tokens)?;
    config.source_files = files;
    Ok(config)
}

#[cfg(test)]
mod tests;
