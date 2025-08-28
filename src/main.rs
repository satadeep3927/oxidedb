mod auth;
mod cli;
mod client;
mod config;
mod database;
mod error;
pub mod grpc;
mod managers;
mod models;

use dotenv::dotenv;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    // Check for CLI mode - everything else defaults to gRPC server
    let args: Vec<String> = std::env::args().collect();
    let cli_mode = args.len() > 1 && args[1] == "cli";

    // Initialize configuration
    let config = config::Config::from_env()?;

    // Initialize database manager
    let db_manager = Arc::new(managers::database::DatabaseManager::new(
        &config.database_path,
    )?);

    // Initialize LLM client
    let llm_client = Arc::new(client::openai::OpenAIClient::new(
        config.llm_api.clone(),
        config.llm_model.clone(),
        config.copilot_access_token.clone(),
        config.debug_mode,
    ));

    // Initialize auth manager
    let auth_manager = Arc::new(auth::AuthManager::new(
        config.jwt_secret.clone(),
        &config.database_path,
        config.root_username.clone(),
        config.root_password.clone(),
    )?);

    if cli_mode {
        // Start CLI interface
        let mut cli = cli::CliInterface::new(db_manager, llm_client, auth_manager);
        cli.run().await?;
    } else {
        // Default: Start gRPC server
        let grpc_service = grpc::OxideDbServiceImpl::new(db_manager, llm_client, auth_manager);

        println!(
            "OxideDB gRPC server starting on port {}",
            config.server_port
        );
        println!("💡 Tip: Use 'oxidedb cli' for interactive CLI mode");

        grpc::start_grpc_server(grpc_service, config.server_port).await?;
    }

    Ok(())
}
