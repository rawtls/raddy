use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use raddy::{
    cloudflare::{Cloudflare, DnsRecord},
    config::Config,
    runtime::Runtime,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "raddy",
    version,
    about = "High-performance HTTP(S) server with Cloudflare DNS-01"
)]
struct Cli {
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Clone)]
enum Command {
    Run {
        #[arg(long, default_value_t = 30)]
        grace_period_secs: u64,
    },
    Validate,
    Dns {
        #[arg(long, env = "RADDY_CLOUDFLARE_API_BASE", hide = true)]
        api_base: Option<String>,
        #[command(subcommand)]
        command: DnsCommand,
    },
}

#[derive(Subcommand, Clone)]
enum DnsCommand {
    Zones,
    List {
        zone: String,
    },
    Add {
        zone: String,
        #[arg(long = "type")]
        kind: String,
        name: String,
        content: String,
        #[arg(long, default_value = "1")]
        ttl: u32,
    },
    Set {
        zone: String,
        #[arg(long = "type")]
        kind: String,
        name: String,
        content: String,
        #[arg(long, default_value = "1")]
        ttl: u32,
    },
    Delete {
        zone: String,
        #[arg(long = "type")]
        kind: String,
        name: String,
        #[arg(default_value = "")]
        content: String,
    },
    Challenge {
        domain: String,
        value: String,
    },
    Cleanup {
        domain: String,
        value: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("raddy=info")),
        )
        .with_target(false)
        .compact()
        .init();
    if let Err(error) = rustls::crypto::ring::default_provider().install_default() {
        eprintln!("failed to initialize TLS cryptography: {error:?}");
        return ExitCode::FAILURE;
    }
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config_path = cli.config.clone().unwrap_or_else(default_config);
    if let Command::Dns { api_base, command } = &cli.command {
        let mut settings = match Config::load(&config_path).await {
            Ok(config) => config.cloudflare_config()?,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                    && !config_path.try_exists()? =>
            {
                let mut settings =
                    raddy::cloudflare::CloudflareConfig::new(std::env::var("CF_API_TOKEN")?);
                settings.zone_token = std::env::var("CF_ZONE_TOKEN")
                    .ok()
                    .filter(|value| !value.is_empty());
                settings
            }
            Err(error) => return Err(error),
        };
        if let Some(base) = api_base {
            settings.api_base = base.clone();
        }
        return dns_command(Cloudflare::new(settings)?, command.clone()).await;
    }
    let config = Config::load(&config_path).await?;
    match cli.command {
        Command::Validate => {
            raddy::acme::validate_configured_certificates(&config).await?;
            let sites = config.sites.len();
            let streams = config.streams.len();
            if sites != 0 {
                tokio::task::spawn_blocking(move || raddy::server::Server::new(config)).await??;
            }
            println!(
                "configuration is valid: {} site(s), {} stream(s): {}",
                sites,
                streams,
                config_path.display()
            );
            Ok(())
        }
        Command::Run { grace_period_secs } => {
            run_server(&config_path, config, Duration::from_secs(grace_period_secs)).await
        }
        Command::Dns { .. } => {
            unreachable!("DNS commands are handled before loading the server configuration")
        }
    }
}

async fn dns_command(client: Cloudflare, command: DnsCommand) -> Result<()> {
    match command {
        DnsCommand::Zones => print_json(&client.list_zones().await?),
        DnsCommand::List { zone } => print_json(&client.get_records(&zone).await?),
        DnsCommand::Add {
            zone,
            kind,
            name,
            content,
            ttl,
        } => print_json(
            &client
                .append_records(&zone, vec![record(kind, name, content, ttl)])
                .await?,
        ),
        DnsCommand::Set {
            zone,
            kind,
            name,
            content,
            ttl,
        } => print_json(
            &client
                .set_records(&zone, vec![record(kind, name, content, ttl)])
                .await?,
        ),
        DnsCommand::Delete {
            zone,
            kind,
            name,
            content,
        } => print_json(
            &client
                .delete_records(&zone, vec![record(kind, name, content, 0)])
                .await?,
        ),
        DnsCommand::Challenge { domain, value } => {
            let zone = client.find_zone_for_name(&domain).await?;
            let name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
            let record = DnsRecord {
                ttl: 120,
                ..DnsRecord::txt(name, value)
            };
            print_json(&client.append_records(&zone.name, vec![record]).await?)
        }
        DnsCommand::Cleanup { domain, value } => {
            let zone = client.find_zone_for_name(&domain).await?;
            let name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
            print_json(
                &client
                    .delete_records(&zone.name, vec![DnsRecord::txt(name, value)])
                    .await?,
            )
        }
    }
}

fn record(kind: String, name: String, content: String, ttl: u32) -> DnsRecord {
    DnsRecord {
        ttl,
        ..DnsRecord::new(kind, name, content)
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn default_config() -> PathBuf {
    for path in ["raddy.json", "Raddyfile", "Caddyfile"].map(Path::new) {
        if path.is_file() {
            return path.to_owned();
        }
    }
    PathBuf::from("raddy.json")
}

async fn run_server(path: &Path, config: Config, grace: Duration) -> Result<()> {
    let mut runtime = Runtime::new();
    #[cfg(unix)]
    let (mut terminate, mut reload) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::terminate())?,
            signal(SignalKind::user_defined1())?,
        )
    };
    let shutdown = async {
        #[cfg(unix)]
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await
    };
    tokio::pin!(shutdown);
    let result = tokio::select! {
        result = &mut shutdown => result.map_err(Into::into),
        result = async {
            runtime.apply(config).await?;
            #[cfg(unix)]
            loop {
                tokio::select! {
                    result = runtime.wait() => break result,
                    _ = reload.recv() => {
                        let result = async { runtime.apply(Config::load(path).await?).await }.await;
                        match result {
                            Ok(()) => tracing::info!(config = %path.display(), "configuration reloaded"),
                            Err(error) => tracing::warn!(config = %path.display(), error = %format_args!("{error:#}"), "reload rejected; keeping active configuration"),
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            runtime.wait().await
        } => result,
    };
    tracing::info!(grace_secs = grace.as_secs(), "shutting down listeners");
    runtime.shutdown(grace).await;
    result
}
