use crate::models::{User, Claims, CreateUserRequest, LoginRequest, LoginResponse};
use crate::error::{OxideError, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use rusqlite::{Connection, params};
use uuid::Uuid;

pub struct AuthManager {
    jwt_secret: String,
    db_path: String,
    root_username: String,
    root_password: String,
}

impl AuthManager {
    pub fn new(jwt_secret: String, data_path: &str, root_username: String, root_password: String) -> Result<Self> {
        let db_path = format!("{}/AUTH", data_path);
        let auth_manager = AuthManager {
            jwt_secret,
            db_path,
            root_username,
            root_password,
        };
        
        auth_manager.init_db()?;
        Ok(auth_manager)
    }
    
    fn init_db(&self) -> Result<()> {
        // Ensure the data directory exists
        if let Some(parent) = std::path::Path::new(&self.db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        println!("Initializing auth database at: {}", self.db_path);
        
        let conn = Connection::open(&self.db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                namespaces TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;
        
        Ok(())
    }
    
    pub fn verify_root_auth(&self, root_username: &str, root_password: &str) -> bool {
        println!("Verifying root auth: {} vs {}, {} vs {}", 
                 root_username, self.root_username, 
                 root_password, self.root_password);
        root_username == self.root_username && root_password == self.root_password
    }
    
    pub fn create_user(&self, request: CreateUserRequest) -> Result<User> {
        let conn = Connection::open(&self.db_path)?;
        
        let password_hash = hash(&request.password, DEFAULT_COST)
            .map_err(|e| OxideError::Auth(format!("Failed to hash password: {}", e)))?;
        
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: request.username,
            password_hash,
            namespaces: request.namespaces,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        let namespaces_json = serde_json::to_string(&user.namespaces)?;
        
        conn.execute(
            "INSERT INTO users (id, username, password_hash, namespaces, created_at, updated_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                user.id,
                user.username,
                user.password_hash,
                namespaces_json,
                user.created_at.to_rfc3339(),
                user.updated_at.to_rfc3339()
            ],
        )?;
        
        Ok(user)
    }
    
    pub fn login(&self, request: LoginRequest) -> Result<LoginResponse> {
        let conn = Connection::open(&self.db_path)?;
        
        let mut stmt = conn.prepare(
            "SELECT id, username, password_hash, namespaces FROM users WHERE username = ?1"
        )?;
        
        let user_row = stmt.query_row(params![request.username], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        }).map_err(|_| OxideError::Auth("Invalid credentials".to_string()))?;
        
        let (user_id, username, password_hash, namespaces_json) = user_row;
        
        if !verify(&request.password, &password_hash)
            .map_err(|e| OxideError::Auth(format!("Password verification failed: {}", e)))? {
            return Err(OxideError::Auth("Invalid credentials".to_string()));
        }
        
        let namespaces: Vec<String> = serde_json::from_str(&namespaces_json)?;
        
        let token = self.generate_token(&user_id, &username, &namespaces)?;
        
        Ok(LoginResponse {
            token,
            user_id,
            namespaces,
        })
    }
    
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let key = DecodingKey::from_secret(self.jwt_secret.as_ref());
        let validation = Validation::default();
        
        let token_data = decode::<Claims>(token, &key, &validation)?;
        Ok(token_data.claims)
    }
    
    fn generate_token(&self, user_id: &str, username: &str, namespaces: &[String]) -> Result<String> {
        let now = Utc::now();
        let exp = (now + Duration::hours(24)).timestamp() as usize;
        let iat = now.timestamp() as usize;
        
        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            namespaces: namespaces.to_vec(),
            exp,
            iat,
        };
        
        let key = EncodingKey::from_secret(self.jwt_secret.as_ref());
        let token = encode(&Header::default(), &claims, &key)?;
        
        Ok(token)
    }
    
    #[allow(dead_code)]
    pub fn authorize_namespace(&self, claims: &Claims, namespace: &str) -> Result<()> {
        if !claims.namespaces.contains(&namespace.to_string()) {
            return Err(OxideError::Authorization(
                format!("Access denied to namespace: {}", namespace)
            ));
        }
        Ok(())
    }
}
