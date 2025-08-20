use thiserror::Error;

#[derive(Error, Debug)]
pub enum CortexError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    
    #[error("Authentication error: {0}")]
    Auth(String),
    
    #[error("Authorization error: {0}")]
    Authorization(String),
    
    #[error("LLM client error: {0}")]
    LlmClient(#[from] reqwest::Error),
    
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[allow(dead_code)]
    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),
    
    #[allow(dead_code)]
    #[error("Database not found: {0}")]
    DatabaseNotFound(String),
    
    #[allow(dead_code)]
    #[error("Invalid SQL query: {0}")]
    InvalidSql(String),
}

pub type Result<T> = std::result::Result<T, CortexError>;
