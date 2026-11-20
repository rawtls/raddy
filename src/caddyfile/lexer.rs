use std::{path::PathBuf, sync::Arc};

use anyhow::{Result, anyhow};

#[derive(Clone, Debug)]
pub struct Token {
    pub text: String,
    pub line: usize,
    pub column: usize,
    pub new_line: bool,
    pub quoted: bool,
    pub source: Option<Arc<PathBuf>>,
    pub structural: bool,
}

impl Token {
    pub fn error(&self, message: impl std::fmt::Display) -> anyhow::Error {
        if let Some(source) = &self.source {
            anyhow!(
                "{}:{}:{}: {message}",
                source.display(),
                self.line,
                self.column
            )
        } else {
            anyhow!("{}:{}: {message}", self.line, self.column)
        }
    }
}

pub fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut lexer = Lexer::new(input.strip_prefix('\u{feff}').unwrap_or(input));
    let mut tokens = Vec::new();
    let mut previous_end = 0;
    while let Some(character) = lexer.peek() {
        if character.is_whitespace() {
            lexer.bump();
            continue;
        }
        if character == '#' {
            while lexer.peek().is_some_and(|character| character != '\n') {
                lexer.bump();
            }
            continue;
        }
        if lexer.is_structural_brace() {
            tokens.push(Token {
                text: character.to_string(),
                line: lexer.line,
                column: lexer.column,
                new_line: lexer.line != previous_end,
                quoted: false,
                source: None,
                structural: true,
            });
            previous_end = lexer.line;
            lexer.bump();
            continue;
        }
        let line = lexer.line;
        let column = lexer.column;
        let mut value = String::new();
        let mut quoted = false;
        while let Some(character) = lexer.peek() {
            if character.is_whitespace() || character == '#' || lexer.is_structural_brace() {
                break;
            }
            match character {
                '"' | '`' => {
                    quoted = true;
                    let raw = character == '`';
                    lexer.bump();
                    loop {
                        match lexer.bump() {
                            Some(character) if character == if raw { '`' } else { '"' } => break,
                            Some('\\') if !raw => match lexer.bump() {
                                Some('"') => value.push('"'),
                                Some('\\') => value.push('\\'),
                                Some('n') => value.push('\n'),
                                Some('r') => value.push('\r'),
                                Some('t') => value.push('\t'),
                                Some('\n') => {}
                                Some(escape) => {
                                    return Err(anyhow!(
                                        "{}:{}: unsupported escape \\{escape}",
                                        lexer.line,
                                        lexer.column
                                    ));
                                }
                                None => {
                                    return Err(anyhow!("{line}:{column}: unterminated escape"));
                                }
                            },
                            Some(character) => value.push(character),
                            None => {
                                return Err(anyhow!("{line}:{column}: unterminated quoted string"));
                            }
                        }
                    }
                }
                _ => {
                    value.push(character);
                    lexer.bump();
                }
            }
        }
        tokens.push(Token {
            text: crate::config::expand_env_placeholders(&value)?,
            line,
            column,
            new_line: line != previous_end,
            quoted,
            source: None,
            structural: false,
        });
        previous_end = lexer.line;
    }
    Ok(tokens)
}

struct Lexer<'a> {
    input: &'a str,
    offset: usize,
    line: usize,
    column: usize,
    placeholder: bool,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            offset: 0,
            line: 1,
            column: 1,
            placeholder: false,
        }
    }

    fn rest(&self) -> &'a str {
        &self.input[self.offset..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn is_structural_brace(&self) -> bool {
        match self.peek() {
            Some('{') => !self.starts_placeholder(),
            Some('}') => !self.placeholder,
            _ => false,
        }
    }

    fn starts_placeholder(&self) -> bool {
        let Some(rest) = self.rest().strip_prefix('{') else {
            return false;
        };
        if let Some(indices) = rest.strip_prefix("args[") {
            let length = indices
                .bytes()
                .take_while(|byte| byte.is_ascii_digit() || *byte == b':')
                .count();
            if indices.as_bytes().get(length..length + 2) == Some(b"]}") {
                return true;
            }
        }
        let length = rest
            .bytes()
            .take_while(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'?')
            })
            .count();
        length != 0 && rest.as_bytes().get(length) == Some(&b'}')
    }

    fn bump(&mut self) -> Option<char> {
        if self.starts_placeholder() {
            self.placeholder = true;
        }
        let character = self.peek()?;
        self.offset += character.len_utf8();
        if character == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        if character == '}' && self.placeholder {
            self.placeholder = false;
        }
        Some(character)
    }
}
