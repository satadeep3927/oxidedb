use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    pub query: String,
    pub mode: QueryMode,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryMode {
    Sql,
    Ai,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub namespaces: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub namespaces: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    pub namespaces: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub username: String,
    pub namespaces: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    #[allow(dead_code)]
    pub namespace: String,
    #[allow(dead_code)]
    pub database: String,
    pub path: String,
}
