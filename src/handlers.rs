use crate::auth::AuthManager;
use crate::client::openai::OpenAIClient;
use crate::managers::database::DatabaseManager;
use crate::models::{QueryRequest, QueryResponse, CreateUserRequest, LoginRequest, Claims};
use crate::error::CortexError;
use warp::{Filter, Reply, Rejection};
use std::sync::Arc;
use std::time::Instant;
use serde_json::json;

// Custom rejection for our errors
#[derive(Debug)]
struct CustomRejection(#[allow(dead_code)] CortexError);
impl warp::reject::Reject for CustomRejection {}

// Error recovery function
async fn handle_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    if let Some(custom_rejection) = err.find::<CustomRejection>() {
        let error_message = match &custom_rejection.0 {
            CortexError::Database(db_err) => {
                // Handle specific database errors
                if db_err.to_string().contains("UNIQUE constraint failed: users.username") {
                    json!({
                        "error": "User already exists",
                        "message": "A user with this username already exists"
                    })
                } else {
                    json!({
                        "error": "Database error",
                        "message": format!("Database operation failed: {}", db_err)
                    })
                }
            },
            CortexError::Auth(msg) => {
                json!({
                    "error": "Authentication failed",
                    "message": msg
                })
            },
            CortexError::Authorization(msg) => {
                json!({
                    "error": "Authorization failed", 
                    "message": msg
                })
            },
            _ => {
                json!({
                    "error": "Internal server error",
                    "message": custom_rejection.0.to_string()
                })
            }
        };
        
        Ok(warp::reply::with_status(
            warp::reply::json(&error_message),
            warp::http::StatusCode::BAD_REQUEST
        ))
    } else if err.is_not_found() {
        Ok(warp::reply::with_status(
            warp::reply::json(&json!({
                "error": "Not found",
                "message": "The requested resource was not found"
            })),
            warp::http::StatusCode::NOT_FOUND
        ))
    } else {
        Ok(warp::reply::with_status(
            warp::reply::json(&json!({
                "error": "Internal server error",
                "message": "An unexpected error occurred"
            })),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR
        ))
    }
}

pub fn routes(
    db_manager: Arc<DatabaseManager>,
    llm_client: Arc<OpenAIClient>,
    auth_manager: Arc<AuthManager>,
) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type", "authorization", "ns", "db", "root-username", "root-password"])
        .allow_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"]);

    let auth_routes = auth_route(auth_manager.clone())
        .or(register_route(auth_manager.clone()));

    let protected_routes = query_route(db_manager, llm_client, auth_manager);

    auth_routes
        .or(protected_routes)
        .with(cors)
        .recover(handle_rejection)
}

fn auth_route(
    auth_manager: Arc<AuthManager>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("login"))
        .and(warp::post())
        .and(warp::body::json())
        .and(with_auth_manager(auth_manager))
        .and_then(login_handler)
}

fn register_route(
    auth_manager: Arc<AuthManager>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("register"))
        .and(warp::post())
        .and(warp::body::json())
        .and(extract_root_auth())
        .and(with_auth_manager(auth_manager))
        .and_then(register_handler)
}

fn query_route(
    db_manager: Arc<DatabaseManager>,
    llm_client: Arc<OpenAIClient>,
    auth_manager: Arc<AuthManager>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("query")
        .and(warp::post())
        .and(warp::body::json())
        .and(extract_headers())
        .and(extract_auth(auth_manager))
        .and(with_db_manager(db_manager))
        .and(with_llm_client(llm_client))
        .and_then(query_handler)
}

fn with_auth_manager(
    auth_manager: Arc<AuthManager>,
) -> impl Filter<Extract = (Arc<AuthManager>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || auth_manager.clone())
}

fn with_db_manager(
    db_manager: Arc<DatabaseManager>,
) -> impl Filter<Extract = (Arc<DatabaseManager>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db_manager.clone())
}

fn with_llm_client(
    llm_client: Arc<OpenAIClient>,
) -> impl Filter<Extract = (Arc<OpenAIClient>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || llm_client.clone())
}

fn extract_headers() -> impl Filter<Extract = (String, String), Error = Rejection> + Clone {
    warp::header::<String>("ns")
        .and(warp::header::<String>("db"))
}

fn extract_root_auth() -> impl Filter<Extract = (String, String), Error = Rejection> + Clone {
    warp::header::<String>("root-username")
        .and(warp::header::<String>("root-password"))
}

fn extract_auth(
    auth_manager: Arc<AuthManager>,
) -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::<String>("authorization")
        .and(with_auth_manager(auth_manager))
        .and_then(|auth_header: String, auth_manager: Arc<AuthManager>| async move {
            let token = auth_header.strip_prefix("Bearer ").unwrap_or(&auth_header);
            match auth_manager.verify_token(token) {
                Ok(claims) => Ok(claims),
                Err(e) => Err(warp::reject::custom(CustomRejection(e))),
            }
        })
}

async fn login_handler(
    request: LoginRequest,
    auth_manager: Arc<AuthManager>,
) -> std::result::Result<impl Reply, Rejection> {
    match auth_manager.login(request) {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => Err(warp::reject::custom(CustomRejection(e))),
    }
}

async fn register_handler(
    request: CreateUserRequest,
    root_username: String,
    root_password: String,
    auth_manager: Arc<AuthManager>,
) -> std::result::Result<impl Reply, Rejection> {
    println!("Received registration request for user: {}", request.username);
    
    // Verify root authentication
    if !auth_manager.verify_root_auth(&root_username, &root_password) {
        println!("Root authentication failed");
        return Err(warp::reject::custom(CustomRejection(
            CortexError::Auth("Invalid root credentials".to_string())
        )));
    }
    
    match auth_manager.create_user(request) {
        Ok(user) => {
            println!("User created successfully: {}", user.username);
            let response = json!({
                "id": user.id,
                "username": user.username,
                "namespaces": user.namespaces,
                "created_at": user.created_at
            });
            Ok(warp::reply::json(&response))
        },
        Err(e) => {
            println!("User creation failed: {}", e);
            Err(warp::reject::custom(CustomRejection(e)))
        },
    }
}

async fn query_handler(
    request: QueryRequest,
    namespace: String,
    database: String,
    claims: Claims,
    db_manager: Arc<DatabaseManager>,
    llm_client: Arc<OpenAIClient>,
) -> std::result::Result<impl Reply, Rejection> {
    let start_time = Instant::now();
    
    // Check authorization for namespace
    if !claims.namespaces.contains(&namespace) {
        return Err(warp::reject::custom(CustomRejection(
            CortexError::Authorization(format!("Access denied to namespace: {}", namespace))
        )));
    }
    
    let database_arc = match db_manager.get_database(&namespace, &database) {
        Ok(db) => db,
        Err(e) => return Err(warp::reject::custom(CustomRejection(e))),
    };
    
    let result = match request.mode {
        crate::models::QueryMode::Sql => {
            // Direct SQL execution
            database_arc.execute_query(&request.query)
        },
        crate::models::QueryMode::Ai => {
            // Generate SQL from natural language
            let schema_info = match database_arc.get_schema_info() {
                Ok(schema) => schema,
                Err(e) => return Err(warp::reject::custom(CustomRejection(e))),
            };
            
            let sql = match llm_client.generate_sql(&request.query, &schema_info).await {
                Ok(sql) => sql,
                Err(e) => return Err(warp::reject::custom(CustomRejection(e))),
            };
            
            database_arc.execute_query(&sql)
        },
    };
    
    let execution_time = start_time.elapsed().as_millis() as u64;
    
    let response = match result {
        Ok(data) => QueryResponse {
            success: true,
            data: Some(data),
            error: None,
            execution_time_ms: execution_time,
        },
        Err(e) => QueryResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
            execution_time_ms: execution_time,
        },
    };
    
    Ok(warp::reply::json(&response))
}
