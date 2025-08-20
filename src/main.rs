mod client;
mod config;
mod managers;
mod auth;
mod database;
mod handlers;
mod models;
mod error;

use std::sync::Arc;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    
    // Initialize configuration
    let config = config::Config::from_env()?;
    
    // Initialize database manager
    let db_manager = Arc::new(managers::database::DatabaseManager::new(&config.database_path)?);
    
    // Initialize LLM client
    let llm_client = Arc::new(client::openai::OpenAIClient::new(
        config.llm_api.clone(),
        config.llm_model.clone(),
        config.llm_api_key.clone(),
    ));
    
    // Initialize auth manager
    let auth_manager = Arc::new(auth::AuthManager::new(
        config.jwt_secret.clone(), 
        &config.database_path,
        config.root_username.clone(),
        config.root_password.clone()
    )?);
    
    // Setup routes
    let routes = handlers::routes(db_manager, llm_client, auth_manager);
    
    println!("CortexDB server starting on port {}", config.server_port);
    
    warp::serve(routes)
        .run(([127, 0, 0, 1], config.server_port))
        .await;
    
    Ok(())
}
