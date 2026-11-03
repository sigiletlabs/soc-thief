//! soc-thief-console: a read-only view of one Soc Thief snapshot file.
//!
//! It never talks to Wazuh, Discord or any model. It reads the snapshot JSON
//! described in `docs/SNAPSHOT.md` and re-reads it when the file changes.

mod snapshot;
mod source;
mod tui;
mod web;

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "soc-thief-console",
    version,
    about = "Read-only terminal and local web view of a Soc Thief snapshot"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the snapshot in the terminal.
    Tui {
        /// Snapshot file to read.
        #[arg(long, default_value = "snapshot.json")]
        snapshot: PathBuf,
    },
    /// Serve the snapshot as a local web page (loopback only, read-only).
    Web {
        /// Snapshot file to read.
        #[arg(long, default_value = "snapshot.json")]
        snapshot: PathBuf,
        /// Address to listen on. Must be a loopback address.
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Tui { snapshot } => tui::run(source::SnapshotSource::new(snapshot)),
        Command::Web { snapshot, listen } => {
            if let Err(e) = web::check_listen(listen) {
                eprintln!("soc-thief-console: {e}");
                return ExitCode::from(2);
            }
            let src = source::SnapshotSource::new(snapshot);
            if let Some(e) = src.error() {
                eprintln!(
                    "soc-thief-console: warning: {e}; serving the error state until the file is readable"
                );
            }
            match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(web::serve(src, listen)),
                Err(e) => Err(e),
            }
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("soc-thief-console: {e}");
            ExitCode::FAILURE
        }
    }
}
