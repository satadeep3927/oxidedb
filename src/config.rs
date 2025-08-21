use crate::error::{CortexError, Result};
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub llm_api: String,
    pub llm_model: String,
    pub llm_api_key: String,
    pub jwt_secret: String,
    pub database_path: String,
    pub server_port: u16,
    pub root_username: String,
    pub root_password: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // Get default database path in home directory
        let default_db_path = match dirs::home_dir() {
            Some(home) => home.join(".cortexdb").to_string_lossy().to_string(),
            None => "./data".to_string(), // Fallback to current directory
        };
        
        Ok(Config {
            llm_api: env::var("LLM_API")
                .unwrap_or("https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
            llm_model: env::var("LLM_MODEL")
                .unwrap_or("gemma-3-4b-it".to_string()),
            llm_api_key: env::var("LLM_API_KEY")
                .unwrap_or("AIzaSyD9QLdgI1rAbh_c36gWXWN6dscHoz3eKM0".to_string()),
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or("JK764fJKiw87cJHW6JHkdsh56jskkYd".to_string()),
            database_path: env::var("DATABASE_PATH").unwrap_or(default_db_path),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "11597".to_string())
                .parse()
                .map_err(|_| CortexError::InvalidRequest("Invalid SERVER_PORT".to_string()))?,
            root_username: env::var("ROOT_USERNAME")
                .unwrap_or("root".to_string()),
            root_password: env::var("ROOT_PASSWORD")
                .unwrap_or("root".to_string()),
        })
    }
}
