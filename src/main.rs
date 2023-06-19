use clap::{Parser, Subcommand};

mod aws_sso;
mod config;

use aws_sso::SSO;
use config::Config;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
    sso_session: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Refresh,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let sso_session_name = args.sso_session.unwrap_or(String::from("default"));
    let config = Config::load_from_env().await;
    let sso = SSO::new(config);
    let _output = match args.command {
        None | Some(Commands::Refresh) => sso.refresh(sso_session_name.as_str()).await,
    };
}
