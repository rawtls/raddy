use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use anyhow::{Result, bail};
use cel::{Context, Env, FunctionContext, Program, RuntimeOptions, Value, extractors::Arguments};
use regex::Regex;

pub(crate) struct Expression {
    source: String,
    program: Program,
    placeholders: Vec<(String, String)>,
}

impl PartialEq for Expression {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for Expression {}

impl Expression {
    pub(crate) fn new(source: &str) -> Result<Self> {
        if source.len() > 8192 || source.is_empty() {
            bail!("CEL matcher requires 1 to 8192 bytes");
        }
        static PLACEHOLDER: OnceLock<Regex> = OnceLock::new();
        let pattern = PLACEHOLDER.get_or_init(|| {
            Regex::new(r"\\?\{([A-Za-z][A-Za-z0-9_.-]+)\}").expect("valid placeholder pattern")
        });
        let mut placeholders = Vec::new();
        let mut names = HashMap::new();
        let expanded = pattern.replace_all(source, |capture: &regex::Captures<'_>| {
            if let Some(literal) = capture[0].strip_prefix('\\') {
                return literal.to_owned();
            }
            let name = &capture[1];
            if let Some(variable) = names.get(name) {
                return String::clone(variable);
            }
            let variable = format!("__raddy_placeholder_{}", placeholders.len());
            placeholders.push((variable.clone(), name.to_owned()));
            names.insert(name.to_owned(), variable.clone());
            variable
        });
        let program = environment().compile(&expanded)?;
        let refs = program.references();
        for name in refs.variables() {
            if !placeholders.iter().any(|(variable, _)| variable == name)
                && !matches!(
                    name,
                    "bool"
                        | "bytes"
                        | "double"
                        | "int"
                        | "list"
                        | "map"
                        | "null_type"
                        | "string"
                        | "type"
                        | "uint"
                )
            {
                bail!("unknown CEL variable {name:?}");
            }
        }
        if let cel::common::ast::Expr::Literal(literal) = &program.expression().expr
            && !matches!(literal, cel::common::ast::LiteralValue::Boolean(_))
        {
            bail!("CEL matcher must return bool");
        }
        Ok(Self {
            source: source.to_owned(),
            program,
            placeholders,
        })
    }

    pub(crate) fn matches(&self, resolve: impl Fn(&str) -> Value) -> Result<bool> {
        let mut context = Context::with_env(environment().clone());
        for (variable, name) in &self.placeholders {
            context.add_variable_from_value(variable.as_str(), resolve(name));
        }
        let references = self.program.references();
        if references.has_function("method") {
            context.add_variable_from_value("__raddy_method", resolve("method"));
            context.add_function("method", method)?;
        }
        if references.has_function("path") {
            context
                .add_variable_from_value("__raddy_path", resolve("http.request.uri.path.escaped"));
            context.add_function("path", crate::server::expression_path)?;
        }
        match self.program.execute(&context)? {
            Value::Bool(matched) => Ok(matched),
            _ => bail!("CEL matcher must return bool"),
        }
    }
}

fn method(
    context: &FunctionContext<'_, '_>,
    Arguments(values): Arguments,
) -> std::result::Result<bool, cel::ExecutionError> {
    let Some(current) = context.ptx.get_variable("__raddy_method") else {
        return Ok(false);
    };
    let Some(current) = current.downcast_ref::<cel::common::types::CelString>() else {
        return Ok(false);
    };
    for value in values.iter() {
        let Value::String(candidate) = value else {
            return Err(context.error("method expects string arguments"));
        };
        if candidate.as_str() == current.inner() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn environment() -> &'static Arc<Env> {
    static ENVIRONMENT: OnceLock<Arc<Env>> = OnceLock::new();
    ENVIRONMENT.get_or_init(|| {
        let mut env = Env::stdlib();
        env.set_options(RuntimeOptions::default().with_max_iterations(4096));
        Arc::new(env)
    })
}
