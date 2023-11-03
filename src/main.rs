use clap::Parser;
use tokio::io::Result;

use cync_rs::*;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long, default_value = "certs/identity.p12")]
    certificate: String,
    #[clap(short, long, default_value_t = 8080)]
    port: u16,
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(match cli.verbose {
            0 => tracing::Level::ERROR,
            1 => tracing::Level::INFO,
            2 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        })
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber)
        .expect("Unable to create tracing subscriber");

    let controller = CyncController::new(cli.certificate.clone(), cli.port);

    controller.run().await;

    Ok(())
}
