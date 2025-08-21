use crate::auth::AuthManager;
use crate::client::openai::OpenAIClient;
use crate::error::{CortexError, Result};
use crate::managers::database::DatabaseManager;
use crate::models::{QueryRequest, LoginRequest, QueryMode as ModelsQueryMode};
use serde_json::Value;
use std::io::{self, Write};
use std::sync::Arc;

pub struct CliInterface {
    db_manager: Arc<DatabaseManager>,
    llm_client: Arc<OpenAIClient>,
    auth_manager: Arc<AuthManager>,
    current_mode: QueryMode,
    current_namespace: Option<String>,
    current_database: Option<String>,
    auth_token: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum QueryMode {
    Sql,
    Ai,
}

impl std::fmt::Display for QueryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryMode::Sql => write!(f, "SQL"),
            QueryMode::Ai => write!(f, "AI"),
        }
    }
}

impl CliInterface {
    pub fn new(
        db_manager: Arc<DatabaseManager>,
        llm_client: Arc<OpenAIClient>,
        auth_manager: Arc<AuthManager>,
    ) -> Self {
        Self {
            db_manager,
            llm_client,
            auth_manager,
            current_mode: QueryMode::Sql,
            current_namespace: None,
            current_database: None,
            auth_token: None,
            username: None,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        println!("🚀 Welcome to CortexDB Interactive CLI");
        println!("Type '/help' for available commands");
        self.print_status();

        loop {
            self.print_prompt();
            
            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_err() {
                continue;
            }
            
            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            if input.starts_with('/') {
                if let Err(e) = self.handle_command(input).await {
                    println!("❌ Error: {}", e);
                }
            } else {
                if let Err(e) = self.handle_query(input).await {
                    println!("❌ Query Error: {}", e);
                }
            }
        }
    }

    fn print_prompt(&self) {
        let mode_indicator = match self.current_mode {
            QueryMode::Sql => "sql",
            QueryMode::Ai => "ai",
        };
        
        let context = if let (Some(ns), Some(db)) = (&self.current_namespace, &self.current_database) {
            format!("{}:{}", ns, db)
        } else {
            "no-context".to_string()
        };

        let user_indicator = self.username.as_ref().map(|u| format!("@{}", u)).unwrap_or_else(|| "@guest".to_string());
        
        print!("cortexdb{}[{}]{}> ", user_indicator, context, mode_indicator);
        io::stdout().flush().unwrap();
    }

    fn print_status(&self) {
        println!();
        println!("📊 Current Status:");
        println!("   Mode: {}", self.current_mode);
        println!("   User: {}", self.username.as_ref().unwrap_or(&"Not logged in".to_string()));
        println!("   Namespace: {}", self.current_namespace.as_ref().unwrap_or(&"None".to_string()));
        println!("   Database: {}", self.current_database.as_ref().unwrap_or(&"None".to_string()));
        println!();
    }

    async fn handle_command(&mut self, command: &str) -> Result<()> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        
        match parts.first().copied() {
            Some("/help") => self.show_help(),
            Some("/set") => self.handle_set_command(&parts[1..]).await?,
            Some("/login") => self.handle_login(&parts[1..]).await?,
            Some("/logout") => self.handle_logout(),
            Some("/use") => self.handle_use_command(&parts[1..])?,
            Some("/show") => self.handle_show_command(&parts[1..]).await?,
            Some("/status") => self.print_status(),
            Some("/quit") | Some("/exit") => {
                println!("👋 Goodbye!");
                std::process::exit(0);
            }
            _ => println!("❓ Unknown command: {}. Type '/help' for available commands.", command),
        }
        
        Ok(())
    }

    fn show_help(&self) {
        println!();
        println!("📖 CortexDB CLI Commands:");
        println!();
        println!("🔧 Settings:");
        println!("   /set ai              - Switch to AI query mode");
        println!("   /set sql             - Switch to SQL query mode");
        println!();
        println!("🔐 Authentication:");
        println!("   /login <username>    - Login to CortexDB");
        println!("   /logout              - Logout from current session");
        println!();
        println!("🗄️ Database Context:");
        println!("   /use <namespace> <database> - Set current namespace and database");
        println!();
        println!("📊 Information:");
        println!("   /show databases      - List all available databases");
        println!("   /show namespaces     - List all available namespaces");
        println!("   /show tables         - List tables in current database");
        println!("   /status              - Show current session status");
        println!();
        println!("🚪 Exit:");
        println!("   /quit, /exit         - Exit the CLI");
        println!();
        println!("💡 Query Examples:");
        println!("   CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
        println!("   SELECT * FROM users");
        println!("   Show me all users with age greater than 25");
        println!();
    }

    async fn handle_set_command(&mut self, args: &[&str]) -> Result<()> {
        match args.get(0) {
            Some(&"ai") => {
                self.current_mode = QueryMode::Ai;
                println!("🤖 Switched to AI query mode");
            }
            Some(&"sql") => {
                self.current_mode = QueryMode::Sql;
                println!("🗄️ Switched to SQL query mode");
            }
            _ => {
                println!("❓ Usage: /set [ai|sql]");
            }
        }
        Ok(())
    }

    async fn handle_login(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("❓ Usage: /login <username>");
            return Ok(());
        }

        let username = args[0];
        print!("🔐 Password for {}: ", username);
        io::stdout().flush().unwrap();

        let password = rpassword::read_password().map_err(|_| {
            CortexError::InvalidRequest("Failed to read password".to_string())
        })?;

        let login_request = LoginRequest {
            username: username.to_string(),
            password,
        };

        match self.auth_manager.login(login_request) {
            Ok(response) => {
                self.auth_token = Some(response.token);
                self.username = Some(response.user_id);
                println!("✅ Login successful! Welcome, {}", username);
                
                if !response.namespaces.is_empty() {
                    println!("📁 Available namespaces: {}", response.namespaces.join(", "));
                }
            }
            Err(e) => {
                println!("❌ Login failed: {}", e);
            }
        }

        Ok(())
    }

    fn handle_logout(&mut self) {
        self.auth_token = None;
        self.username = None;
        self.current_namespace = None;
        self.current_database = None;
        println!("👋 Logged out successfully");
    }

    fn handle_use_command(&mut self, args: &[&str]) -> Result<()> {
        if args.len() != 2 {
            println!("❓ Usage: /use <namespace> <database>");
            return Ok(());
        }

        let namespace = args[0].to_string();
        let database = args[1].to_string();

        // TODO: Validate that user has access to this namespace/database
        self.current_namespace = Some(namespace.clone());
        self.current_database = Some(database.clone());
        
        println!("📂 Switched to namespace: {}, database: {}", namespace, database);
        Ok(())
    }

    async fn handle_show_command(&mut self, args: &[&str]) -> Result<()> {
        match args.get(0) {
            Some(&"namespaces") => {
                if self.auth_token.is_none() {
                    println!("❌ Please login first");
                    return Ok(());
                }
                
                match self.db_manager.list_namespaces() {
                    Ok(namespaces) => {
                        println!("📁 Available namespaces:");
                        for ns in namespaces {
                            println!("   • {}", ns);
                        }
                    }
                    Err(e) => println!("❌ Failed to list namespaces: {}", e),
                }
            }
            Some(&"databases") => {
                if let Some(namespace) = &self.current_namespace {
                    match self.db_manager.list_databases(namespace) {
                        Ok(databases) => {
                            println!("🗄️ Databases in namespace '{}':", namespace);
                            for db in databases {
                                println!("   • {}", db);
                            }
                        }
                        Err(e) => println!("❌ Failed to list databases: {}", e),
                    }
                } else {
                    println!("❌ Please set a namespace first with: /use <namespace> <database>");
                }
            }
            Some(&"tables") => {
                if let (Some(namespace), Some(database)) = (&self.current_namespace, &self.current_database) {
                    match self.db_manager.get_database(namespace, database) {
                        Ok(db) => {
                            let query_result = db.execute_query(
                                "SELECT name FROM sqlite_master WHERE type='table';"
                            );
                            
                            match query_result {
                                Ok(result) => {
                                    println!("📋 Tables in {}.{}:", namespace, database);
                                    if let Value::Array(rows) = result {
                                        for row in rows {
                                            if let Value::Object(obj) = row {
                                                if let Some(Value::String(name)) = obj.get("name") {
                                                    println!("   • {}", name);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => println!("❌ Failed to list tables: {}", e),
                            }
                        }
                        Err(e) => println!("❌ Failed to access database: {}", e),
                    }
                } else {
                    println!("❌ Please set namespace and database first with: /use <namespace> <database>");
                }
            }
            _ => {
                println!("❓ Usage: /show [namespaces|databases|tables]");
            }
        }
        Ok(())
    }

    async fn handle_query(&mut self, query: &str) -> Result<()> {
        if self.auth_token.is_none() {
            println!("❌ Please login first with: /login <username>");
            return Ok(());
        }

        if self.current_namespace.is_none() || self.current_database.is_none() {
            println!("❌ Please set namespace and database first with: /use <namespace> <database>");
            return Ok(());
        }

        let namespace = self.current_namespace.as_ref().unwrap().clone();
        let database = self.current_database.as_ref().unwrap().clone();

        let query_request = QueryRequest {
            query: query.to_string(),
            mode: match self.current_mode {
                QueryMode::Sql => ModelsQueryMode::Sql,
                QueryMode::Ai => ModelsQueryMode::Ai,
            },
        };

        println!("⏳ Executing {} query...", self.current_mode);

        // Get database connection
        let database = self.db_manager.get_database(&namespace, &database)?;

        let result = if self.current_mode == QueryMode::Ai {
            // AI mode: convert natural language to SQL first
            let schema_info = ""; // For now, we'll implement this later
            let sql_query = self.llm_client.generate_sql(&query_request.query, schema_info).await?;
            println!("🤖 Generated SQL: {}", sql_query);
            
            database.execute_query(&sql_query)?
        } else {
            // SQL mode: execute directly
            database.execute_query(&query_request.query)?
        };

        // Pretty print results
        self.print_query_result(&result);
        Ok(())
    }

    fn print_query_result(&self, result: &Value) {
        println!();
        match result {
            Value::Array(rows) if rows.is_empty() => {
                println!("📭 No results found");
            }
            Value::Array(rows) => {
                println!("📊 Query Results ({} rows):", rows.len());
                println!();
                
                // Print as table if possible
                if let Some(first_row) = rows.first() {
                    if let Value::Object(obj) = first_row {
                        // Print headers
                        let headers: Vec<String> = obj.keys().map(|k| k.clone()).collect();
                        println!("   {}", headers.join(" | "));
                        println!("   {}", headers.iter().map(|h| "-".repeat(h.len())).collect::<Vec<_>>().join("-+-"));
                        
                        // Print rows
                        for row in rows {
                            if let Value::Object(row_obj) = row {
                                let values: Vec<String> = headers.iter()
                                    .map(|h| {
                                        row_obj.get(h)
                                            .map(|v| match v {
                                                Value::String(s) => s.clone(),
                                                Value::Number(n) => n.to_string(),
                                                Value::Bool(b) => b.to_string(),
                                                Value::Null => "NULL".to_string(),
                                                _ => serde_json::to_string(v).unwrap_or_else(|_| "?".to_string()),
                                            })
                                            .unwrap_or_else(|| "NULL".to_string())
                                    })
                                    .collect();
                                println!("   {}", values.join(" | "));
                            }
                        }
                    }
                }
            }
            Value::Object(obj) => {
                println!("📊 Query Result:");
                for (key, value) in obj {
                    println!("   {}: {}", key, value);
                }
            }
            _ => {
                println!("📊 Query Result: {}", serde_json::to_string_pretty(result).unwrap_or_else(|_| "Unknown".to_string()));
            }
        }
        println!();
    }
}
