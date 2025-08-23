use crate::auth::AuthManager;
use crate::client::openai::OpenAIClient;
use crate::error::{OxideError, Result};
use crate::managers::database::DatabaseManager;
use crate::models::{CreateUserRequest, LoginRequest as ModelLoginRequest};
use prost_types;
use std::sync::Arc;
use std::time::Instant;
use tonic::{transport::Server, Request, Response, Status};

// Include the generated protobuf code
pub mod oxide_db {
    tonic::include_proto!("oxidedb");
}

use oxide_db::{
    oxide_db_service_server::{OxideDbService, OxideDbServiceServer},
    *,
};

// Helper function to convert serde_json::Value to prost_types::Struct
fn json_value_to_prost_struct(value: &serde_json::Value) -> prost_types::Struct {
    use std::collections::BTreeMap;
    let mut fields = BTreeMap::new();

    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                fields.insert(key.clone(), json_value_to_prost_value(val));
            }
        }
        _ => {
            // If it's not an object, wrap it in a "value" field
            fields.insert("value".to_string(), json_value_to_prost_value(value));
        }
    }

    prost_types::Struct { fields }
}

fn json_value_to_prost_value(value: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;

    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Kind::NumberValue(i as f64)
            } else if let Some(f) = n.as_f64() {
                Kind::NumberValue(f)
            } else {
                Kind::StringValue(n.to_string())
            }
        }
        serde_json::Value::String(s) => Kind::StringValue(s.clone()),
        serde_json::Value::Array(arr) => {
            let list_value = prost_types::ListValue {
                values: arr.iter().map(json_value_to_prost_value).collect(),
            };
            Kind::ListValue(list_value)
        }
        serde_json::Value::Object(_) => Kind::StructValue(json_value_to_prost_struct(value)),
    };

    prost_types::Value { kind: Some(kind) }
}

pub struct OxideDbServiceImpl {
    db_manager: Arc<DatabaseManager>,
    llm_client: Arc<OpenAIClient>,
    auth_manager: Arc<AuthManager>,
}

impl OxideDbServiceImpl {
    pub fn new(
        db_manager: Arc<DatabaseManager>,
        llm_client: Arc<OpenAIClient>,
        auth_manager: Arc<AuthManager>,
    ) -> Self {
        Self {
            db_manager,
            llm_client,
            auth_manager,
        }
    }
}

#[tonic::async_trait]
impl OxideDbService for OxideDbServiceImpl {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> std::result::Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();

        let login_req = ModelLoginRequest {
            username: req.username,
            password: req.password,
        };

        match self.auth_manager.login(login_req) {
            Ok(response) => {
                let reply = LoginResponse {
                    token: response.token,
                    user_id: response.user_id,
                    namespaces: response.namespaces,
                    success: true,
                    error: String::new(),
                };
                Ok(Response::new(reply))
            }
            Err(e) => {
                let reply = LoginResponse {
                    token: String::new(),
                    user_id: String::new(),
                    namespaces: vec![],
                    success: false,
                    error: e.to_string(),
                };
                Ok(Response::new(reply))
            }
        }
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> std::result::Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        // Verify root authentication
        if !self
            .auth_manager
            .verify_root_auth(&req.root_username, &req.root_password)
        {
            let reply = RegisterResponse {
                user_id: String::new(),
                success: false,
                error: "Invalid root credentials".to_string(),
            };
            return Ok(Response::new(reply));
        }

        let create_req = CreateUserRequest {
            username: req.username,
            password: req.password,
            namespaces: req.namespaces,
        };

        match self.auth_manager.create_user(create_req) {
            Ok(user) => {
                let reply = RegisterResponse {
                    user_id: user.id,
                    success: true,
                    error: String::new(),
                };
                Ok(Response::new(reply))
            }
            Err(e) => {
                let reply = RegisterResponse {
                    user_id: String::new(),
                    success: false,
                    error: e.to_string(),
                };
                Ok(Response::new(reply))
            }
        }
    }

    async fn execute_query(
        &self,
        request: Request<QueryRequest>,
    ) -> std::result::Result<Response<QueryResponse>, Status> {
        let req = request.into_inner();
        let start_time = Instant::now();

        // Verify token
        let claims = match self.auth_manager.verify_token(&req.token) {
            Ok(claims) => claims,
            Err(e) => {
                let reply = QueryResponse {
                    success: false,
                    data: None,
                    error: e.to_string(),
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                    rows_affected: 0,
                };
                return Ok(Response::new(reply));
            }
        };

        // Check namespace access
        if !claims.namespaces.contains(&req.namespace) {
            let reply = QueryResponse {
                success: false,
                data: None,
                error: "Access denied to namespace".to_string(),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                rows_affected: 0,
            };
            return Ok(Response::new(reply));
        }

        // Get database connection
        let database = match self.db_manager.get_database(&req.namespace, &req.database) {
            Ok(db) => db,
            Err(e) => {
                let reply = QueryResponse {
                    success: false,
                    data: None,
                    error: e.to_string(),
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                    rows_affected: 0,
                };
                return Ok(Response::new(reply));
            }
        };

        // Execute query based on mode
        let query_result = match req.mode() {
            QueryMode::Sql => database.execute_query(&req.query),
            QueryMode::Ai => match database.get_schema_info() {
                Ok(schema) => match self.llm_client.generate_sql(&req.query, &schema).await {
                    Ok(sql) => database.execute_query(&sql),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
        };

        let execution_time = start_time.elapsed().as_millis() as u64;

        match query_result {
            Ok(data) => {
                // Convert serde_json::Value to prost Struct using helper function
                let struct_data = json_value_to_prost_struct(&data);

                let reply = QueryResponse {
                    success: true,
                    data: Some(query_response::Data::StructuredData(struct_data)),
                    error: String::new(),
                    execution_time_ms: execution_time,
                    rows_affected: 0, // TODO: Extract from data
                };
                Ok(Response::new(reply))
            }
            Err(e) => {
                let reply = QueryResponse {
                    success: false,
                    data: None,
                    error: e.to_string(),
                    execution_time_ms: execution_time,
                    rows_affected: 0,
                };
                Ok(Response::new(reply))
            }
        }
    }

    async fn get_schema_info(
        &self,
        request: Request<SchemaRequest>,
    ) -> std::result::Result<Response<SchemaResponse>, Status> {
        let req = request.into_inner();

        // Verify token
        let claims = match self.auth_manager.verify_token(&req.token) {
            Ok(claims) => claims,
            Err(e) => {
                let reply = SchemaResponse {
                    schema_info: String::new(),
                    success: false,
                    error: e.to_string(),
                };
                return Ok(Response::new(reply));
            }
        };

        // Check namespace access
        if !claims.namespaces.contains(&req.namespace) {
            let reply = SchemaResponse {
                schema_info: String::new(),
                success: false,
                error: "Access denied to namespace".to_string(),
            };
            return Ok(Response::new(reply));
        }

        // Get database connection
        let database = match self.db_manager.get_database(&req.namespace, &req.database) {
            Ok(db) => db,
            Err(e) => {
                let reply = SchemaResponse {
                    schema_info: String::new(),
                    success: false,
                    error: e.to_string(),
                };
                return Ok(Response::new(reply));
            }
        };

        match database.get_schema_info() {
            Ok(schema) => {
                let reply = SchemaResponse {
                    schema_info: schema,
                    success: true,
                    error: String::new(),
                };
                Ok(Response::new(reply))
            }
            Err(e) => {
                let reply = SchemaResponse {
                    schema_info: String::new(),
                    success: false,
                    error: e.to_string(),
                };
                Ok(Response::new(reply))
            }
        }
    }

    async fn list_namespaces(
        &self,
        request: Request<ListNamespacesRequest>,
    ) -> std::result::Result<Response<ListNamespacesResponse>, Status> {
        let req = request.into_inner();

        // Verify token
        let claims = match self.auth_manager.verify_token(&req.token) {
            Ok(claims) => claims,
            Err(e) => {
                let reply = ListNamespacesResponse {
                    namespaces: vec![],
                    success: false,
                    error: e.to_string(),
                };
                return Ok(Response::new(reply));
            }
        };

        let reply = ListNamespacesResponse {
            namespaces: claims.namespaces,
            success: true,
            error: String::new(),
        };
        Ok(Response::new(reply))
    }

    async fn list_databases(
        &self,
        request: Request<ListDatabasesRequest>,
    ) -> std::result::Result<Response<ListDatabasesResponse>, Status> {
        let req = request.into_inner();

        // Verify token
        let claims = match self.auth_manager.verify_token(&req.token) {
            Ok(claims) => claims,
            Err(e) => {
                let reply = ListDatabasesResponse {
                    databases: vec![],
                    success: false,
                    error: e.to_string(),
                };
                return Ok(Response::new(reply));
            }
        };

        // Check namespace access
        if !claims.namespaces.contains(&req.namespace) {
            let reply = ListDatabasesResponse {
                databases: vec![],
                success: false,
                error: "Access denied to namespace".to_string(),
            };
            return Ok(Response::new(reply));
        }

        match self.db_manager.list_databases(&req.namespace) {
            Ok(databases) => {
                let reply = ListDatabasesResponse {
                    databases,
                    success: true,
                    error: String::new(),
                };
                Ok(Response::new(reply))
            }
            Err(e) => {
                let reply = ListDatabasesResponse {
                    databases: vec![],
                    success: false,
                    error: e.to_string(),
                };
                Ok(Response::new(reply))
            }
        }
    }

    async fn create_database(
        &self,
        request: Request<CreateDatabaseRequest>,
    ) -> std::result::Result<Response<CreateDatabaseResponse>, Status> {
        let req = request.into_inner();

        // Verify token
        let claims = match self.auth_manager.verify_token(&req.token) {
            Ok(claims) => claims,
            Err(e) => {
                let reply = CreateDatabaseResponse {
                    success: false,
                    error: e.to_string(),
                };
                return Ok(Response::new(reply));
            }
        };

        // Check namespace access
        if !claims.namespaces.contains(&req.namespace) {
            let reply = CreateDatabaseResponse {
                success: false,
                error: "Access denied to namespace".to_string(),
            };
            return Ok(Response::new(reply));
        }

        // Creating a database connection essentially creates the database
        match self.db_manager.get_database(&req.namespace, &req.database) {
            Ok(_) => {
                let reply = CreateDatabaseResponse {
                    success: true,
                    error: String::new(),
                };
                Ok(Response::new(reply))
            }
            Err(e) => {
                let reply = CreateDatabaseResponse {
                    success: false,
                    error: e.to_string(),
                };
                Ok(Response::new(reply))
            }
        }
    }

    async fn delete_database(
        &self,
        request: Request<DeleteDatabaseRequest>,
    ) -> std::result::Result<Response<DeleteDatabaseResponse>, Status> {
        let req = request.into_inner();

        // Verify token
        let claims = match self.auth_manager.verify_token(&req.token) {
            Ok(claims) => claims,
            Err(e) => {
                let reply = DeleteDatabaseResponse {
                    success: false,
                    error: e.to_string(),
                };
                return Ok(Response::new(reply));
            }
        };

        // Check namespace access
        if !claims.namespaces.contains(&req.namespace) {
            let reply = DeleteDatabaseResponse {
                success: false,
                error: "Access denied to namespace".to_string(),
            };
            return Ok(Response::new(reply));
        }

        match self
            .db_manager
            .delete_database(&req.namespace, &req.database)
        {
            Ok(_) => {
                let reply = DeleteDatabaseResponse {
                    success: true,
                    error: String::new(),
                };
                Ok(Response::new(reply))
            }
            Err(e) => {
                let reply = DeleteDatabaseResponse {
                    success: false,
                    error: e.to_string(),
                };
                Ok(Response::new(reply))
            }
        }
    }
}

pub async fn start_grpc_server(service: OxideDbServiceImpl, port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port).parse().unwrap();

    println!("Starting gRPC server on {}", addr);

    Server::builder()
        .add_service(OxideDbServiceServer::new(service))
        .serve(addr)
        .await
        .map_err(|e| OxideError::InvalidRequest(format!("gRPC server error: {}", e)))?;

    Ok(())
}
