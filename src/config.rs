use std::env;
use crate::error::{CortexError, Result};

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
        Ok(Config {
            llm_api: env::var("LLM_API")
                .map_err(|_| CortexError::InvalidRequest("LLM_API not set".to_string()))?,
            llm_model: env::var("LLM_MODEL")
                .map_err(|_| CortexError::InvalidRequest("LLM_MODEL not set".to_string()))?,
            llm_api_key: env::var("LLM_API_KEY")
                .map_err(|_| CortexError::InvalidRequest("LLM_API_KEY not set".to_string()))?,
            jwt_secret: env::var("JWT_SECRET")
                .map_err(|_| CortexError::InvalidRequest("JWT_SECRET not set".to_string()))?,
            database_path: env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "./data".to_string()),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3030".to_string())
                .parse()
                .map_err(|_| CortexError::InvalidRequest("Invalid SERVER_PORT".to_string()))?,
            root_username: env::var("ROOT_USERNAME")
                .map_err(|_| CortexError::InvalidRequest("ROOT_USERNAME not set".to_string()))?,
            root_password: env::var("ROOT_PASSWORD")
                .map_err(|_| CortexError::InvalidRequest("ROOT_PASSWORD not set".to_string()))?,
        })
    }
}
