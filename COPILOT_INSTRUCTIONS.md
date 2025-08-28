# OxideDB Client Library SDK - Copilot Instructions

## Overview
Create comprehensive client libraries (SDKs) for connecting to OxideDB via gRPC protocol. Support multiple programming languages with consistent APIs, proper error handling, abstraction methods (create, read, update, delete), and comprehensive documentation.

## Protocol Architecture

### gRPC Service
OxideDB uses **gRPC exclusively** for client communication, providing high-performance binary communication with strong typing and efficient serialization.

**Server Details:**
- **Protocol**: gRPC (HTTP/2)
- **Default Port**: 11597  
- **Address**: 127.0.0.1:11597
- **Service**: `oxidedb.OxideDbService`

### Authentication
All gRPC requests require JWT authentication via metadata:
```
Authorization: Bearer <jwt_token>
```

## gRPC Service Definition

### Core Methods

#### 1. Authentication
```protobuf
rpc Login(LoginRequest) returns (LoginResponse);
rpc Register(RegisterRequest) returns (RegisterResponse);
```

#### 2. Query Operations
```protobuf
rpc ExecuteQuery(QueryRequest) returns (QueryResponse);
rpc GetSchemaInfo(SchemaRequest) returns (SchemaResponse);
```

#### 3. Database Management
```protobuf
rpc ListNamespaces(ListNamespacesRequest) returns (ListNamespacesResponse);
rpc ListDatabases(ListDatabasesRequest) returns (ListDatabasesResponse);
rpc CreateDatabase(CreateDatabaseRequest) returns (CreateDatabaseResponse);
rpc DeleteDatabase(DeleteDatabaseRequest) returns (DeleteDatabaseResponse);
```

### Message Types

#### Authentication Messages
```protobuf
message LoginRequest {
  string username = 1;
  string password = 2;
}

message LoginResponse {
  string token = 1;
  string user_id = 2;
  repeated string namespaces = 3;
  bool success = 4;
  string error = 5;
}
```

#### 2. Query Execution
```http
POST /query
Authorization: Bearer <token>
Content-Type: application/json

{
  "query": "SELECT * FROM users",
  "mode": "sql",  // "sql" or "ai"
  "namespace": "my_namespace",
  "database": "my_database"
}

Response:
{
  "success": true,
  "data": [
    {"id": 1, "name": "John"},
    {"id": 2, "name": "Jane"}
  ],
  "execution_time_ms": 45,
  "rows_affected": 2
}
```

## Client Library Architecture with Abstraction Methods

### Core Abstraction Methods - Knex.js Inspired API

Client libraries should provide a Knex.js-inspired query builder with fluent method chaining for intuitive database operations:

#### CREATE Operations (Knex-style)

```javascript
// Table creation
await db.schema.createTable('users', function (table) {
  table.increments('id');
  table.string('name');
  table.string('email').unique();
  table.integer('age');
  table.timestamps();
});

// Insert operations
await db('users').insert({
  name: 'John Doe',
  email: 'john@example.com',
  age: 30
});

// Batch insert
await db('users').insert([
  { name: 'Alice', email: 'alice@example.com', age: 25 },
  { name: 'Bob', email: 'bob@example.com', age: 35 }
]);
```

#### READ Operations (Knex-style)

```javascript
// Basic select
const users = await db('users').select('*');

// Select specific columns
const users = await db('users').select('id', 'name', 'email');

// Where conditions
const user = await db('users').where('id', 1).first();
const activeUsers = await db('users').where('status', 'active');

// Complex where conditions
const results = await db('users')
  .where('age', '>', 18)
  .andWhere('status', 'active')
  .orWhere('role', 'admin');

// Multiple where conditions
const filtered = await db('users')
  .where('age', '>=', 21)
  .whereIn('status', ['active', 'premium'])
  .whereNotNull('email');

// Joins
const userProfiles = await db('users')
  .join('profiles', 'users.id', 'profiles.user_id')
  .select('users.name', 'profiles.bio');

// Left join
const usersWithProfiles = await db('users')
  .leftJoin('profiles', 'users.id', 'profiles.user_id')
  .select('users.*', 'profiles.bio');

// Order and limit
const recentUsers = await db('users')
  .orderBy('created_at', 'desc')
  .limit(10);

// Pagination
const paginatedUsers = await db('users')
  .orderBy('id')
  .limit(20)
  .offset(40);

// Aggregations
const userCount = await db('users').count('* as total');
const avgAge = await db('users').avg('age as average_age');
const totalRevenue = await db('orders').sum('amount as total');

// Group by and having
const usersByStatus = await db('users')
  .select('status')
  .count('* as count')
  .groupBy('status')
  .having('count', '>', 5);
```

#### UPDATE Operations (Knex-style)

```javascript
// Update single record
await db('users').where('id', 1).update({
  name: 'John Smith',
  updated_at: db.fn.now()
});

// Update multiple records
await db('users')
  .where('status', 'inactive')
  .update({ status: 'archived' });

// Update with conditions
await db('products')
  .where('category', 'electronics')
  .andWhere('stock', '>', 0)
  .update({ 
    discount: 0.1,
    updated_at: db.fn.now()
  });

// Increment/decrement
await db('users').where('id', 1).increment('login_count', 1);
await db('products').where('id', 1).decrement('stock', 5);
```

#### DELETE Operations (Knex-style)

```javascript
// Delete single record
await db('users').where('id', 1).del();

// Delete multiple records
await db('users')
  .where('last_login', '<', '2023-01-01')
  .del();

// Delete with complex conditions
await db('posts')
  .where('status', 'draft')
  .andWhere('created_at', '<', db.raw('NOW() - INTERVAL 30 DAY'))
  .del();
```

#### AI-Enhanced Operations (Knex-style)

```javascript
// Natural language query
const results = await db.ai("Show me all users who joined this month");

// AI query with parameters
const insights = await db.ai("What are the top selling products?")
  .from('orders')
  .join('products', 'orders.product_id', 'products.id');

// AI explanation
const explanation = await db.ai.explain(queryResults);
```

#### Schema Operations (Knex-style)

```javascript
// Create table with schema builder
await db.schema.createTable('posts', function (table) {
  table.increments('id');
  table.string('title').notNullable();
  table.text('content');
  table.integer('user_id').references('id').inTable('users');
  table.enum('status', ['draft', 'published', 'archived']).defaultTo('draft');
  table.timestamps(true, true);
});

// Alter table
await db.schema.alterTable('users', function (table) {
  table.string('phone').nullable();
  table.boolean('is_verified').defaultTo(false);
});

// Drop table
await db.schema.dropTable('old_table');

// Check if table exists
const exists = await db.schema.hasTable('users');
```

### 1. Rust Client Library (Knex-inspired)

```rust
// oxidedb-client/src/lib.rs  
use tonic::transport::Channel;
use tonic::{Request, Response, Status};
use std::collections::HashMap;
use serde_json::Value;
use anyhow::Result;

pub mod proto {
    tonic::include_proto!("oxidedb");
}

use proto::{
    oxide_db_service_client::OxideDbServiceClient,
    LoginRequest, LoginResponse, QueryRequest, QueryResponse,
    QueryMode, CreateDatabaseRequest, DeleteDatabaseRequest,
};

#[derive(Debug, thiserror::Error)]
pub enum OxideDbError {
    #[error("Connection error: {0}")]
    Connection(#[from] tonic::transport::Error),
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),
    #[error("Authentication failed: {0}")]
    Auth(String),
    #[error("Query failed: {0}")]
    Query(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Configuration error: {0}")]
    Config(String),
}

// Main client - Knex-style entry point
#[derive(Debug, Clone)]
pub struct OxideDb {
    client: OxideDbServiceClient<Channel>,
    token: Option<String>,
    namespace: Option<String>,
    database: Option<String>,
}

impl OxideDb {
    /// Connect to OxideDB server
    pub async fn connect(address: &str) -> Result<Self, OxideDbError> {
        let client = OxideDbServiceClient::connect(address).await?;
        Ok(Self {
            client,
            token: None,
            namespace: None,
            database: None,
        })
    }

    /// Authenticate with username and password
    pub async fn authenticate(mut self, username: &str, password: &str) -> Result<Self, OxideDbError> {
        let request = Request::new(LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        });

        let response = self.client.login(request).await?;
        let login_response = response.into_inner();

        if !login_response.success {
            return Err(OxideDbError::Auth(login_response.error));
        }

        self.token = Some(login_response.token);
        Ok(self)
    }

    /// Select namespace and database
    pub fn use_db(mut self, namespace: &str, database: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self.database = Some(database.to_string());
        self
    }

    // Knex-style table function - main entry point
    pub fn table(&self, table: &str) -> QueryBuilder {
        QueryBuilder::new(self.clone(), table)
    }

    // Shorthand syntax - Knex style: db("table_name")
    pub fn call(&self, table: &str) -> QueryBuilder {
        self.table(table)
    }

    // Schema builder
    pub fn schema(&self) -> SchemaBuilder {
        SchemaBuilder::new(self.clone())
    }

    // AI query interface
    pub fn ai(&self) -> AiBuilder {
        AiBuilder::new(self.clone())
    }

    // Raw SQL execution
    pub async fn raw(&self, query: &str) -> Result<Vec<Value>, OxideDbError> {
        let mut db = self.clone();
        let result = db.execute_sql(query).await?;
        db.extract_data_array(result)
    }

    // Internal helper methods
    async fn execute_sql(&mut self, query: &str) -> Result<QueryResponse, OxideDbError> {
        self.execute_query(query, QueryMode::Sql).await
    }

    async fn execute_query(&mut self, query: &str, mode: QueryMode) -> Result<QueryResponse, OxideDbError> {
        let token = self.token.as_ref().ok_or_else(|| OxideDbError::Auth("Not authenticated".to_string()))?;
        let namespace = self.namespace.as_ref().ok_or_else(|| OxideDbError::Config("Namespace not set".to_string()))?;
        let database = self.database.as_ref().ok_or_else(|| OxideDbError::Config("Database not set".to_string()))?;

        let request = serde_json::json!({
            "query": query_string,
            "mode": self.current_mode.as_str(),
            "namespace": namespace,
            "database": database
        });

        let response = timeout(
            self.timeout,
            self.client
                .post(&format!("{}/query", self.base_url))
                .header("Authorization", format!("Bearer {}", token))
                .json(&request)
                .send()
        ).await
        .map_err(|_| CortexDBError::Timeout("Query request timed out".to_string()))?
        .map_err(CortexDBError::HttpError)?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(CortexDBError::QueryError(error_text));
        }

        Ok(response.json().await?)
    }

    pub async fn sql(&self, query_string: &str) -> Result<QueryResponse> {
        let mut temp_self = self.clone();
        temp_self.current_mode = QueryMode::Sql;
        temp_self.query(query_string).await
    }

    pub async fn ai(&self, query_string: &str) -> Result<QueryResponse> {
        let mut temp_self = self.clone();
        temp_self.current_mode = QueryMode::Ai;
        temp_self.query(query_string).await
    }

    // Getters
    pub fn namespace(&self) -> Option<&str> {
        self.current_namespace.as_deref()
    }

    pub fn where_gt<T: Into<Value>>(self, column: &str, value: T) -> Self {
        self.where_(column, ">", value)
    }

    pub fn where_gte<T: Into<Value>>(self, column: &str, value: T) -> Self {
        self.where_(column, ">=", value)
    }

    pub fn where_lt<T: Into<Value>>(self, column: &str, value: T) -> Self {
        self.where_(column, "<", value)
    }

    pub fn where_lte<T: Into<Value>>(self, column: &str, value: T) -> Self {
        self.where_(column, "<=", value)
    }

    pub fn set_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }
}

// Usage examples
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn example_basic_usage() -> Result<()> {
        let db = CortexDB::new()
            .authenticate("username", "password").await?
            .use_db("test", "test")
            .set("sql")?;

        // Execute SQL query
        let result = db.query("SELECT * FROM users LIMIT 10").await?;
        println!("SQL Result: {:?}", result.data);

        // Switch to AI mode and execute
        let ai_result = db.set("ai")?.query("show me all users created last week").await?;
        println!("AI Result: {:?}", ai_result.data);

        Ok(())
    }

    #[tokio::test]
    async fn example_convenience_methods() -> Result<()> {
        let db = CortexDB::new()
            .authenticate("username", "password").await?
            .use_db("test", "test");

        // Convenience methods
        let sql_result = db.sql("SELECT COUNT(*) FROM users").await?;
        let ai_result = db.ai("how many users do we have?").await?;

        println!("SQL Count: {:?}", sql_result.data);
        println!("AI Count: {:?}", ai_result.data);

        Ok(())
    }

    #[tokio::test]
    async fn example_chaining() -> Result<()> {
        // Everything in one chain
        let result = CortexDB::with_url("http://localhost:11597/api/v1")
            .timeout(Duration::from_secs(60))
            .authenticate("admin", "password").await?
            .use_db("production", "analytics")
            .set("ai")?
            .query("show me the top 10 customers by revenue").await?;

        println!("Chained result: {:?}", result.data);
        Ok(())
    }
}
```

### 2. Python Client Library

```python
# cortexdb_client/__init__.py
import asyncio
import aiohttp
import json
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass
from enum import Enum

class QueryMode(Enum):
    SQL = "sql"
    AI = "ai"

@dataclass
class LoginResponse:
    token: str
    user_id: str
    expires_at: str

@dataclass
class QueryResponse:
    success: bool
    data: Any
    execution_time_ms: int
    rows_affected: Optional[int] = None
    error: Optional[str] = None

class CortexDBError(Exception):
    """Base exception for CortexDB client errors"""
    pass

class AuthError(CortexDBError):
    """Authentication related errors"""
    pass

class QueryError(CortexDBError):
    """Query execution errors"""
    pass

class ConfigError(CortexDBError):
    """Configuration errors"""
    pass

class CortexDB:
    """
    Fluent CortexDB client with method chaining support
    
    Example:
        db = await CortexDB().authenticate('user', 'pass').use('test', 'test').set('sql')
        result = await db.query('SELECT * FROM users')
    """
    
    def __init__(self, base_url: str = "http://localhost:11597/api/v1"):
        self.base_url = base_url
        self.timeout = 30
        self._token: Optional[str] = None
        self._namespace: Optional[str] = None
        self._database: Optional[str] = None
        self._mode: QueryMode = QueryMode.SQL
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    def with_timeout(self, timeout: int) -> 'CortexDB':
        """Set request timeout and return self for chaining"""
        self.timeout = timeout
        return self

    async def authenticate(self, username: str, password: str) -> 'CortexDB':
        """Authenticate with CortexDB and return self for chaining"""
        if not self._session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )

        payload = {
            "username": username,
            "password": password
        }

        try:
            async with self._session.post(
                f"{self.base_url}/auth/login",
                json=payload
            ) as response:
                if not response.ok:
                    error_text = await response.text()
                    raise AuthError(f"Authentication failed: {error_text}")
                
                data = await response.json()
                self._token = data["token"]
                return self

        except aiohttp.ClientError as e:
            raise CortexDBError(f"HTTP request failed: {e}")

    def use(self, namespace: str, database: str) -> 'CortexDB':
        """Set namespace and database, return self for chaining"""
        self._namespace = namespace
        self._database = database
        return self

    def set(self, mode: str) -> 'CortexDB':
        """Set query mode (sql|ai) and return self for chaining"""
        if mode == "sql":
            self._mode = QueryMode.SQL
        elif mode == "ai":
            self._mode = QueryMode.AI
        else:
            raise ConfigError(f"Invalid mode: {mode}. Use 'sql' or 'ai'")
        return self

    async def query(self, query_string: str) -> QueryResponse:
        """Execute query with current configuration"""
        if not self._token:
            raise AuthError("Not authenticated")
        if not self._namespace:
            raise ConfigError("Namespace not set")
        if not self._database:
            raise ConfigError("Database not set")
        
        if not self._session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )

        payload = {
            "query": query_string,
            "mode": self._mode.value,
            "namespace": self._namespace,
            "database": self._database
        }

        headers = {"Authorization": f"Bearer {self._token}"}

        try:
            async with self._session.post(
                f"{self.base_url}/query",
                json=payload,
                headers=headers
            ) as response:
                if not response.ok:
                    error_text = await response.text()
                    raise QueryError(f"Query failed: {error_text}")
                
                data = await response.json()
                return QueryResponse(
                    success=data["success"],
                    data=data["data"],
                    execution_time_ms=data["execution_time_ms"],
                    rows_affected=data.get("rows_affected"),
                    error=data.get("error")
                )

        except aiohttp.ClientError as e:
            raise CortexDBError(f"HTTP request failed: {e}")

    async def sql(self, query_string: str) -> QueryResponse:
        """Convenience method to execute SQL query"""
        original_mode = self._mode
        self._mode = QueryMode.SQL
        try:
            return await self.query(query_string)
        finally:
            self._mode = original_mode

    async def ai(self, query_string: str) -> QueryResponse:
        """Convenience method to execute AI query"""
        original_mode = self._mode
        self._mode = QueryMode.AI
        try:
            return await self.query(query_string)
        finally:
            self._mode = original_mode

    # Properties for inspection
    @property
    def namespace(self) -> Optional[str]:
        return self._namespace

    @property
    def database(self) -> Optional[str]:
        return self._database

    @property
    def mode(self) -> str:
        return self._mode.value

    @property
    def is_authenticated(self) -> bool:
        return self._token is not None

    def set_token(self, token: str) -> 'CortexDB':
        """Manually set authentication token and return self for chaining"""
        self._token = token
        return self

    async def close(self):
        """Manually close the session"""
        if self._session:
            await self._session.close()
            self._session = None

# Synchronous wrapper for non-async environments
class SyncCortexDB:
    """Synchronous wrapper around async CortexDB client"""
    
    def __init__(self, base_url: str = "http://localhost:11597/api/v1"):
        self._async_client = CortexDB(base_url)
        self._loop = asyncio.new_event_loop()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._loop.run_until_complete(self._async_client.close())
        self._loop.close()

    def authenticate(self, username: str, password: str) -> 'SyncCortexDB':
        self._loop.run_until_complete(
            self._async_client.authenticate(username, password)
        )
        return self

    def use(self, namespace: str, database: str) -> 'SyncCortexDB':
        self._async_client.use(namespace, database)
        return self

    def set(self, mode: str) -> 'SyncCortexDB':
        self._async_client.set(mode)
        return self

    def query(self, query_string: str) -> QueryResponse:
        return self._loop.run_until_complete(
            self._async_client.query(query_string)
        )

    def sql(self, query_string: str) -> QueryResponse:
        return self._loop.run_until_complete(
            self._async_client.sql(query_string)
        )

    def ai(self, query_string: str) -> QueryResponse:
        return self._loop.run_until_complete(
            self._async_client.ai(query_string)
        )

# Usage examples
async def example_async():
    """Async usage example"""
    async with CortexDB() as db:
        # Chain authentication and configuration
        await db.authenticate("username", "password")
        db.use("test", "test").set("sql")

        # Execute queries
        result = await db.query("SELECT * FROM users LIMIT 10")
        print(f"SQL Result: {result.data}")

        # Use convenience methods
        ai_result = await db.ai("show me all users created last week")
        print(f"AI Result: {ai_result.data}")

def example_sync():
    """Synchronous usage example"""
    with SyncCortexDB() as db:
        # Same API but synchronous
        db.authenticate("username", "password").use("test", "test").set("sql")
        
        result = db.query("SELECT COUNT(*) FROM users")
        print(f"User count: {result.data}")

# One-liner examples
async def example_one_liner():
    """Complete operations in one chain"""
    async with CortexDB().with_timeout(60) as db:
        result = await (await db.authenticate("admin", "password")
                       .use("production", "analytics")
                       .set("ai")
                       .query("show me top 10 customers by revenue"))
        
        print(f"Top customers: {result.data}")

if __name__ == "__main__":
    # Run async example
    asyncio.run(example_async())
    
    # Run sync example  
    example_sync()
```

### 3. JavaScript/TypeScript Client Library

```typescript
// cortexdb-client/src/index.ts
export interface LoginResponse {
  token: string;
  user_id: string;
  expires_at: string;
}

export interface QueryResponse {
  success: boolean;
  data: any;
  execution_time_ms: number;
  rows_affected?: number;
  error?: string;
}

export class CortexDBError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CortexDBError';
  }
}

export class AuthenticationError extends CortexDBError {
  constructor(message: string) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class QueryError extends CortexDBError {
  constructor(message: string) {
    super(message);
    this.name = 'QueryError';
  }
}

type QueryMode = 'sql' | 'ai';

export class CortexDB {
  private baseUrl: string;
  private timeout: number;
  private token?: string;
  private currentNamespace?: string;
  private currentDatabase?: string;
  private currentMode: QueryMode = 'sql';

  constructor(baseUrl: string = 'http://localhost:11597/api/v1', timeout: number = 30000) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeout = timeout;
  }

  // Authentication
  async authenticate(username: string, password: string): Promise<CortexDB> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        throw new AuthenticationError(`Authentication failed: ${errorText}`);
      }

      const result: LoginResponse = await response.json();
      this.token = result.token;
      return this;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new CortexDBError('Authentication request timed out');
      }
      throw error;
    }
  }

  // Context selection
  use(namespace: string, database: string): CortexDB {
    this.currentNamespace = namespace;
    this.currentDatabase = database;
    return this;
  }

  // Mode selection
  set(mode: QueryMode): CortexDB {
    this.currentMode = mode;
    return this;
  }

  // Query execution
  async query(queryString: string): Promise<QueryResponse> {
    if (!this.token) {
      throw new AuthenticationError('Not authenticated. Call authenticate() first.');
    }

    if (!this.currentNamespace || !this.currentDatabase) {
      throw new CortexDBError('Namespace and database not set. Call use(namespace, database) first.');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`,
        },
        body: JSON.stringify({
          query: queryString,
          mode: this.currentMode,
          namespace: this.currentNamespace,
          database: this.currentDatabase,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        throw new QueryError(`Query failed: ${errorText}`);
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new CortexDBError('Query request timed out');
      }
      throw error;
    }
  }

  // Convenience methods
  async sql(queryString: string): Promise<QueryResponse> {
    return this.set('sql').query(queryString);
  }

  async ai(queryString: string): Promise<QueryResponse> {
    return this.set('ai').query(queryString);
  }

  // Getters for current state
  getNamespace(): string | undefined {
    return this.currentNamespace;
  }

  getDatabase(): string | undefined {
    return this.currentDatabase;
  }

  getMode(): QueryMode {
    return this.currentMode;
  }

  isAuthenticated(): boolean {
    return !!this.token;
  }

  // Manual token setting (for advanced usage)
  setToken(token: string): CortexDB {
    this.token = token;
    return this;
  }

  // Configuration
  setTimeout(timeout: number): CortexDB {
    this.timeout = timeout;
    return this;
  }
}

// Usage examples
async function basicUsage() {
  const db = new CortexDB();

  try {
    // Fluent API with chaining
    await db
      .authenticate('username', 'password')
      .then(db => db.use('test', 'test'))
      .then(db => db.set('sql'));

    // Execute SQL query
    const sqlResult = await db.query('SELECT * FROM users LIMIT 10');
    console.log('SQL Result:', sqlResult.data);

    // Switch to AI mode and execute
    const aiResult = await db.set('ai').query('show me all users created last week');
    console.log('AI Result:', aiResult.data);

    // Convenience methods
    const quickSql = await db.sql('SELECT COUNT(*) FROM users');
    const quickAi = await db.ai('how many users do we have?');

    console.log('Quick SQL:', quickSql.data);
    console.log('Quick AI:', quickAi.data);

  } catch (error) {
    if (error instanceof AuthenticationError) {
      console.error('Authentication failed:', error.message);
    } else if (error instanceof QueryError) {
      console.error('Query failed:', error.message);
    } else {
      console.error('Unexpected error:', error);
    }
  }
}

async function advancedUsage() {
  const db = new CortexDB('http://localhost:11597/api/v1', 60000); // 60 second timeout

  // Chain everything together
  const result = await db
    .authenticate('admin', 'password')
    .then(db => db.use('production', 'analytics'))
    .then(db => db.set('ai'))
    .then(db => db.query('show me the top 10 customers by revenue'));

  console.log('Advanced result:', result.data);

  // Multiple queries with different modes
  const db2 = new CortexDB().setTimeout(45000);
  await db2.authenticate('user', 'pass');
  await db2.use('test', 'test');

  const users = await db2.sql('SELECT * FROM users');
  const summary = await db2.ai('summarize the user data');
  
  console.log('Users:', users.data);
  console.log('Summary:', summary.data);
}

// React/Vue.js integration example
class CortexDBHook {
  private db: CortexDB;
  private isConnected: boolean = false;

  constructor(baseUrl?: string) {
    this.db = new CortexDB(baseUrl);
  }

  async connect(username: string, password: string, namespace: string, database: string) {
    try {
      await this.db.authenticate(username, password);
      this.db.use(namespace, database);
      this.isConnected = true;
      return true;
    } catch (error) {
      this.isConnected = false;
      throw error;
    }
  }

  async sqlQuery(query: string) {
    if (!this.isConnected) throw new Error('Not connected');
    return await this.db.sql(query);
  }

  async aiQuery(query: string) {
    if (!this.isConnected) throw new Error('Not connected');
    return await this.db.ai(query);
  }

  getStatus() {
    return {
      connected: this.isConnected,
      namespace: this.db.getNamespace(),
      database: this.db.getDatabase(),
      mode: this.db.getMode(),
    };
  }
}

export { CortexDBHook };
```

### 4. Go Client Library

```go
// cortexdb/client.go
package cortexdb

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

type QueryMode string

const (
    SQLMode QueryMode = "sql"
    AIMode  QueryMode = "ai"
)

type LoginResponse struct {
    Token     string `json:"token"`
    UserID    string `json:"user_id"`
    ExpiresAt string `json:"expires_at"`
}

type QueryResponse struct {
    Success         bool        `json:"success"`
    Data           interface{} `json:"data"`
    ExecutionTimeMs int64      `json:"execution_time_ms"`
    RowsAffected   *int64     `json:"rows_affected,omitempty"`
    Error          *string    `json:"error,omitempty"`
}

type CortexDBError struct {
    Type    string
    Message string
}

func (e *CortexDBError) Error() string {
    return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

type CortexDB struct {
    baseURL          string
    httpClient       *http.Client
    token            string
    currentNamespace string
    currentDatabase  string
    currentMode      QueryMode
}

func New() *CortexDB {
    return NewWithURL("http://localhost:11597/api/v1")
}

func NewWithURL(baseURL string) *CortexDB {
    return &CortexDB{
        baseURL: baseURL,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
        currentMode: SQLMode,
    }
}

func (c *CortexDB) WithTimeout(timeout time.Duration) *CortexDB {
    c.httpClient.Timeout = timeout
    return c
}

func (c *CortexDB) Authenticate(ctx context.Context, username, password string) (*CortexDB, error) {
    reqBody := map[string]string{
        "username": username,
        "password": password,
    }

    var resp LoginResponse
    err := c.makeRequest(ctx, "POST", "/auth/login", reqBody, &resp, false)
    if err != nil {
        return c, &CortexDBError{
            Type:    "AuthenticationError",
            Message: err.Error(),
        }
    }

    c.token = resp.Token
    return c, nil
}

func (c *CortexDB) Use(namespace, database string) *CortexDB {
    c.currentNamespace = namespace
    c.currentDatabase = database
    return c
}

func (c *CortexDB) Set(mode string) (*CortexDB, error) {
    switch mode {
    case "sql":
        c.currentMode = SQLMode
    case "ai":
        c.currentMode = AIMode
    default:
        return c, &CortexDBError{
            Type:    "ConfigurationError",
            Message: fmt.Sprintf("Invalid mode: %s. Use 'sql' or 'ai'", mode),
        }
    }
    return c, nil
}

func (c *CortexDB) Query(ctx context.Context, queryString string) (*QueryResponse, error) {
    if c.token == "" {
        return nil, &CortexDBError{
            Type:    "AuthenticationError",
            Message: "Not authenticated",
        }
    }

    if c.currentNamespace == "" {
        return nil, &CortexDBError{
            Type:    "ConfigurationError",
            Message: "Namespace not set",
        }
    }

    if c.currentDatabase == "" {
        return nil, &CortexDBError{
            Type:    "ConfigurationError",
            Message: "Database not set",
        }
    }

    reqBody := map[string]interface{}{
        "query":     queryString,
        "mode":      string(c.currentMode),
        "namespace": c.currentNamespace,
        "database":  c.currentDatabase,
    }

    var resp QueryResponse
    err := c.makeRequest(ctx, "POST", "/query", reqBody, &resp, true)
    if err != nil {
        return nil, &CortexDBError{
            Type:    "QueryError",
            Message: err.Error(),
        }
    }

    return &resp, nil
}

func (c *CortexDB) SQL(ctx context.Context, queryString string) (*QueryResponse, error) {
    originalMode := c.currentMode
    c.currentMode = SQLMode
    defer func() {
        c.currentMode = originalMode
    }()
    return c.Query(ctx, queryString)
}

func (c *CortexDB) AI(ctx context.Context, queryString string) (*QueryResponse, error) {
    originalMode := c.currentMode
    c.currentMode = AIMode
    defer func() {
        c.currentMode = originalMode
    }()
    return c.Query(ctx, queryString)
}

// Getters
func (c *CortexDB) Namespace() string {
    return c.currentNamespace
}

func (c *CortexDB) Database() string {
    return c.currentDatabase
}

func (c *CortexDB) Mode() string {
    return string(c.currentMode)
}

func (c *CortexDB) IsAuthenticated() bool {
    return c.token != ""
}

func (c *CortexDB) SetToken(token string) *CortexDB {
    c.token = token
    return c
}

func (c *CortexDB) makeRequest(ctx context.Context, method, path string, reqBody interface{}, respBody interface{}, requireAuth bool) error {
    var body io.Reader
    if reqBody != nil {
        jsonBody, err := json.Marshal(reqBody)
        if err != nil {
            return fmt.Errorf("failed to marshal request body: %w", err)
        }
        body = bytes.NewReader(jsonBody)
    }

    req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")
    if requireAuth && c.token != "" {
        req.Header.Set("Authorization", "Bearer "+c.token)
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    respBodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode >= 400 {
        return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBodyBytes))
    }

    if respBody != nil {
        if err := json.Unmarshal(respBodyBytes, respBody); err != nil {
            return fmt.Errorf("failed to unmarshal response: %w", err)
        }
    }

    return nil
}

// Usage examples
func ExampleBasicUsage() {
    ctx := context.Background()
    
    // Basic chaining
    db, err := New().
        Authenticate(ctx, "username", "password")
    if err != nil {
        panic(err)
    }
    
    db.Use("test", "test")
    db.Set("sql")
    
    result, err := db.Query(ctx, "SELECT * FROM users LIMIT 10")
    if err != nil {
        panic(err)
    }
    fmt.Printf("SQL Result: %+v\n", result.Data)
    
    // Use convenience methods
    aiResult, err := db.AI(ctx, "show me all users created last week")
    if err != nil {
        panic(err)
    }
    fmt.Printf("AI Result: %+v\n", aiResult.Data)
}

func ExampleConvenienceMethods() {
    ctx := context.Background()
    
    db, err := New().Authenticate(ctx, "username", "password")
    if err != nil {
        panic(err)
    }
    
    db.Use("test", "test")
    
    // SQL and AI convenience methods
    sqlResult, err := db.SQL(ctx, "SELECT COUNT(*) FROM users")
    if err != nil {
        panic(err)
    }
    
    aiResult, err := db.AI(ctx, "how many users do we have?")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("SQL Count: %+v\n", sqlResult.Data)
    fmt.Printf("AI Count: %+v\n", aiResult.Data)
}

func ExampleFullChain() {
    ctx := context.Background()
    
    // Everything in one chain
    db, err := NewWithURL("http://localhost:11597/api/v1").
        WithTimeout(60 * time.Second).
        Authenticate(ctx, "admin", "password")
    if err != nil {
        panic(err)
    }
    
    db.Use("production", "analytics")
    db.Set("ai")
    
    result, err := db.Query(ctx, "show me the top 10 customers by revenue")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Chained result: %+v\n", result.Data)
}
```
```

## Package Structure and Distribution

### Rust Package
```
oxidedb-client/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Main client library
│   ├── proto.rs            # Generated protobuf code
│   └── error.rs            # Error definitions
├── proto/
│   └── oxidedb.proto       # Protobuf definitions
├── examples/
│   └── crud_operations.rs  # Usage examples
└── README.md
```

### Python Package
```
oxidedb-client/
├── setup.py
├── pyproject.toml
├── oxidedb_client/
│   ├── __init__.py         # Main client library
│   ├── client.py           # Core client implementation
│   ├── exceptions.py       # Error definitions
│   └── generated/          # Generated protobuf code
│       ├── __init__.py
│       ├── oxidedb_pb2.py
│       └── oxidedb_pb2_grpc.py
├── examples/
│   └── crud_operations.py  # Usage examples
└── README.md
```

### JavaScript/TypeScript Package  
```
oxidedb-client/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts            # Main client library
│   ├── types.ts            # TypeScript definitions
│   └── generated/          # Generated protobuf code
│       ├── oxidedb_pb.js
│       └── oxidedb_grpc_pb.js
├── examples/
│   ├── crud_operations.js
│   └── react_integration.tsx
└── README.md
```

## Key Benefits of the gRPC Architecture

✅ **High Performance** - Binary protocol with efficient serialization  
✅ **Type Safety** - Strong typing across all languages via protobuf  
✅ **Streaming Support** - Built-in support for streaming operations  
✅ **Cross-Platform** - Native support in all major languages  
✅ **Abstraction Methods** - High-level CRUD operations hide SQL complexity  
✅ **AI Integration** - Natural language query processing  
✅ **Connection Management** - Automatic connection pooling and retries  
✅ **Authentication** - JWT-based security with namespace isolation  

## Development Guidelines

### Client Library Standards
1. **Consistent API** - Same method names and patterns across all languages
2. **Error Handling** - Comprehensive error types and handling patterns
3. **Async Support** - Native async/await patterns where available
4. **Type Safety** - Full type definitions and validation
5. **Documentation** - Complete API docs with examples
6. **Testing** - Unit tests and integration test coverage

### Abstraction Layer Requirements
1. **CRUD Methods** - Create, Read, Update, Delete operations
2. **AI Methods** - Natural language query processing
3. **Schema Methods** - Table and database management
4. **Batch Operations** - Efficient bulk data operations
5. **Transaction Support** - ACID transaction management
6. **Connection Pooling** - Efficient resource management

This gRPC-based architecture provides a modern, efficient, and developer-friendly interface for interacting with OxideDB across multiple programming languages and platforms.
```
```
```
  "success": true,
  "data": [
    {"id": 1, "name": "John"},
    {"id": 2, "name": "Jane"}
  ],
  "execution_time_ms": 45,
  "rows_affected": 2
}
```

#### 3. User Registration
```http
POST /auth/register
Authorization: Bearer <root_token>
Content-Type: application/json

{
  "username": "string",
  "password": "string",
  "root_password": "string"
}

Response:
{
  "success": true,
  "user_id": "uuid",
  "message": "User created successfully"
}
```

## Method Chaining API Design

### Fluent Query Builder Pattern

Implement method chaining for all CRUD operations using a fluent API pattern. This allows developers to build queries using chained methods rather than passing condition strings.

#### CREATE Operations with Chaining

```rust
// Rust Example
let result = db
    .insert("users")
    .values(&[
        ("name", "John Doe"),
        ("email", "john@example.com"),
        ("age", "30")
    ])
    .on_conflict("email")
    .do_update()
    .returning("id")
    .execute()
    .await?;

// Batch insert with chaining
let batch_result = db
    .insert("products")
    .batch()
    .add_row(&[("name", "Product A"), ("price", "19.99")])
    .add_row(&[("name", "Product B"), ("price", "29.99")])
    .add_row(&[("name", "Product C"), ("price", "39.99")])
    .on_duplicate_key_update()
    .execute()
    .await?;
```

```python
# Python Example
result = await (db
    .insert("users")
    .values({
        "name": "John Doe",
        "email": "john@example.com", 
        "age": 30
    })
    .on_conflict("email")
    .do_update()
    .returning("id")
    .execute())

# Batch insert
batch_result = await (db
    .insert("products")
    .batch()
    .add_row({"name": "Product A", "price": 19.99})
    .add_row({"name": "Product B", "price": 29.99})
    .add_row({"name": "Product C", "price": 39.99})
    .on_duplicate_key_update()
    .execute())
```

```javascript
// JavaScript/TypeScript Example
const result = await db
    .insert("users")
    .values({
        name: "John Doe",
        email: "john@example.com",
        age: 30
    })
    .onConflict("email")
    .doUpdate()
    .returning("id")
    .execute();

// Batch insert
const batchResult = await db
    .insert("products")
    .batch()
    .addRow({ name: "Product A", price: 19.99 })
    .addRow({ name: "Product B", price: 29.99 })
    .addRow({ name: "Product C", price: 39.99 })
    .onDuplicateKeyUpdate()
    .execute();
```

#### READ Operations with Chaining

```rust
// Rust Example - Complex SELECT with chaining
let users = db
    .select("users")
    .columns(&["id", "name", "email", "created_at"])
    .where_("age").gte(18)
    .and_where("status").eq("active")
    .or_where("role").in_(&["admin", "moderator"])
    .join("profiles", "users.id = profiles.user_id")
    .join_type("LEFT")
    .order_by("created_at").desc()
    .order_by("name").asc()
    .limit(50)
    .offset(100)
    .group_by(&["status", "role"])
    .having("COUNT(*)").gt(5)
    .execute()
    .await?;

// Aggregation with chaining
let stats = db
    .select("orders")
    .columns(&["COUNT(*) as total_orders", "SUM(amount) as total_revenue"])
    .where_("created_at").between("2024-01-01", "2024-12-31")
    .and_where("status").eq("completed")
    .group_by(&["customer_id"])
    .having("SUM(amount)").gte(1000)
    .execute()
    .await?;
```

```python
# Python Example
users = await (db
    .select("users")
    .columns(["id", "name", "email", "created_at"])
    .where("age").gte(18)
    .and_where("status").eq("active")
    .or_where("role").in_(["admin", "moderator"])
    .join("profiles", "users.id = profiles.user_id")
    .join_type("LEFT")
    .order_by("created_at").desc()
    .order_by("name").asc()
    .limit(50)
    .offset(100)
    .group_by(["status", "role"])
    .having("COUNT(*)").gt(5)
    .execute())

# Aggregation
stats = await (db
    .select("orders")
    .columns(["COUNT(*) as total_orders", "SUM(amount) as total_revenue"])
    .where("created_at").between("2024-01-01", "2024-12-31")
    .and_where("status").eq("completed")
    .group_by(["customer_id"])
    .having("SUM(amount)").gte(1000)
    .execute())
```

```javascript
// JavaScript/TypeScript Example
const users = await db
    .select("users")
    .columns(["id", "name", "email", "created_at"])
    .where("age").gte(18)
    .andWhere("status").eq("active")
    .orWhere("role").in(["admin", "moderator"])
    .join("profiles", "users.id = profiles.user_id")
    .joinType("LEFT")
    .orderBy("created_at").desc()
    .orderBy("name").asc()
    .limit(50)
    .offset(100)
    .groupBy(["status", "role"])
    .having("COUNT(*)").gt(5)
    .execute();

// Aggregation
const stats = await db
    .select("orders")
    .columns(["COUNT(*) as total_orders", "SUM(amount) as total_revenue"])
    .where("created_at").between("2024-01-01", "2024-12-31")
    .andWhere("status").eq("completed")
    .groupBy(["customer_id"])
    .having("SUM(amount)").gte(1000)
    .execute();
```

#### UPDATE Operations with Chaining

```rust
// Rust Example
let updated = db
    .update("users")
    .set("last_login", "NOW()")
    .set("login_count", "login_count + 1")
    .where_("email").eq("john@example.com")
    .and_where("status").eq("active")
    .returning(&["id", "last_login"])
    .execute()
    .await?;

// Conditional update with chaining
let conditional_update = db
    .update("products")
    .set("discount", 0.1)
    .set("updated_at", "NOW()")
    .where_("category").eq("electronics")
    .and_where("stock").gt(0)
    .and_where("price").between(100.0, 1000.0)
    .limit(100)
    .execute()
    .await?;
```

```python
# Python Example
updated = await (db
    .update("users")
    .set("last_login", "NOW()")
    .set("login_count", "login_count + 1")
    .where("email").eq("john@example.com")
    .and_where("status").eq("active")
    .returning(["id", "last_login"])
    .execute())

# Conditional update
conditional_update = await (db
    .update("products")
    .set("discount", 0.1)
    .set("updated_at", "NOW()")
    .where("category").eq("electronics")
    .and_where("stock").gt(0)
    .and_where("price").between(100.0, 1000.0)
    .limit(100)
    .execute())
```

```javascript
// JavaScript/TypeScript Example
const updated = await db
    .update("users")
    .set("last_login", "NOW()")
    .set("login_count", "login_count + 1")
    .where("email").eq("john@example.com")
    .andWhere("status").eq("active")
    .returning(["id", "last_login"])
    .execute();

// Conditional update
const conditionalUpdate = await db
    .update("products")
    .set("discount", 0.1)
    .set("updated_at", "NOW()")
    .where("category").eq("electronics")
    .andWhere("stock").gt(0)
    .andWhere("price").between(100.0, 1000.0)
    .limit(100)
    .execute();
```

#### DELETE Operations with Chaining

```rust
// Rust Example
let deleted = db
    .delete("users")
    .where_("last_login").lt("2023-01-01")
    .and_where("status").eq("inactive")
    .or_where("email").is_null()
    .limit(1000)
    .returning(&["id", "email"])
    .execute()
    .await?;

// Soft delete with chaining
let soft_deleted = db
    .update("posts")  // Soft delete using update
    .set("deleted_at", "NOW()")
    .set("status", "deleted")
    .where_("author_id").eq(user_id)
    .and_where("status").ne("deleted")
    .execute()
    .await?;
```

```python
# Python Example
deleted = await (db
    .delete("users")
    .where("last_login").lt("2023-01-01")
    .and_where("status").eq("inactive")
    .or_where("email").is_null()
    .limit(1000)
    .returning(["id", "email"])
    .execute())

# Soft delete
soft_deleted = await (db
    .update("posts")
    .set("deleted_at", "NOW()")
    .set("status", "deleted")
    .where("author_id").eq(user_id)
    .and_where("status").ne("deleted")
    .execute())
```

```javascript
// JavaScript/TypeScript Example
const deleted = await db
    .delete("users")
    .where("last_login").lt("2023-01-01")
    .andWhere("status").eq("inactive")
    .orWhere("email").isNull()
    .limit(1000)
    .returning(["id", "email"])
    .execute();

// Soft delete
const softDeleted = await db
    .update("posts")
    .set("deleted_at", "NOW()")
    .set("status", "deleted")
    .where("author_id").eq(userId)
    .andWhere("status").ne("deleted")
    .execute();
```

### Advanced Chaining Patterns

#### Subqueries with Chaining

```rust
// Rust Example - Subquery in WHERE clause
let users_with_orders = db
    .select("users")
    .columns(&["id", "name", "email"])
    .where_("id").in_(
        db.select("orders")
          .columns(&["user_id"])
          .where_("created_at").gte("2024-01-01")
          .distinct()
    )
    .execute()
    .await?;

// EXISTS subquery
let active_customers = db
    .select("customers")
    .columns(&["id", "name"])
    .where_exists(
        db.select("orders")
          .where_("orders.customer_id = customers.id")
          .and_where("orders.status").eq("completed")
    )
    .execute()
    .await?;
```

#### Window Functions with Chaining

```rust
// Rust Example - Window functions
let ranked_sales = db
    .select("sales")
    .columns(&[
        "id", 
        "amount", 
        "salesperson_id",
        "ROW_NUMBER() OVER (PARTITION BY salesperson_id ORDER BY amount DESC) as rank"
    ])
    .where_("created_at").between("2024-01-01", "2024-12-31")
    .window("sales_window")
    .partition_by(&["salesperson_id"])
    .order_by("amount").desc()
    .execute()
    .await?;
```

#### Transaction Chaining

```rust
// Rust Example - Transaction with multiple operations
let transaction_result = db
    .begin_transaction()
    .insert("orders")
    .values(&[("customer_id", "123"), ("total", "99.99")])
    .returning(&["id"])
    .then_insert("order_items")
    .values(&[("order_id", "LAST_INSERT_ID()"), ("product_id", "456")])
    .then_update("products")
    .set("stock", "stock - 1")
    .where_("id").eq("456")
    .commit()
    .await?;
```

### Method Chaining API Reference

#### Comparison Operators

- `.eq(value)` - Equal to
- `.ne(value)` - Not equal to
- `.gt(value)` - Greater than
- `.gte(value)` - Greater than or equal
- `.lt(value)` - Less than
- `.lte(value)` - Less than or equal
- `.between(start, end)` - Between two values
- `.in_(values)` - In array/list
- `.not_in(values)` - Not in array/list
- `.like(pattern)` - LIKE pattern matching
- `.ilike(pattern)` - Case-insensitive LIKE
- `.is_null()` - IS NULL
- `.is_not_null()` - IS NOT NULL

#### Logical Operators

- `.and_where(column)` - AND condition
- `.or_where(column)` - OR condition
- `.where_not(column)` - NOT condition
- `.where_exists(subquery)` - EXISTS subquery
- `.where_not_exists(subquery)` - NOT EXISTS subquery

#### Join Methods

- `.join(table, condition)` - INNER JOIN
- `.left_join(table, condition)` - LEFT JOIN
- `.right_join(table, condition)` - RIGHT JOIN
- `.full_join(table, condition)` - FULL OUTER JOIN
- `.cross_join(table)` - CROSS JOIN
- `.join_type(type)` - Set join type

#### Ordering and Grouping

- `.order_by(column)` - ORDER BY column
- `.asc()` - Ascending order
- `.desc()` - Descending order
- `.group_by(columns)` - GROUP BY columns
- `.having(column)` - HAVING condition

#### Limiting and Pagination

- `.limit(count)` - LIMIT rows
- `.offset(count)` - OFFSET rows
- `.page(number, size)` - Pagination helper

#### Advanced Methods

- `.distinct()` - SELECT DISTINCT
- `.returning(columns)` - RETURNING clause
- `.on_conflict(columns)` - ON CONFLICT
- `.do_update()` - DO UPDATE
- `.do_nothing()` - DO NOTHING
- `.window(name)` - Window function
- `.partition_by(columns)` - PARTITION BY

### Usage Examples

```rust
// Complex query example combining multiple patterns
let comprehensive_query = db
    .select("orders")
    .columns(&[
        "o.id",
        "o.total",
        "c.name as customer_name",
        "COUNT(oi.id) as item_count",
        "SUM(oi.quantity) as total_quantity"
    ])
    .from("orders o")
    .join("customers c", "o.customer_id = c.id")
    .left_join("order_items oi", "o.id = oi.order_id")
    .where_("o.created_at").between("2024-01-01", "2024-12-31")
    .and_where("o.status").in_(&["completed", "shipped"])
    .and_where("c.country").eq("US")
    .group_by(&["o.id", "o.total", "c.name"])
    .having("COUNT(oi.id)").gt(0)
    .order_by("o.total").desc()
    .limit(100)
    .execute()
    .await?;
```

This method chaining approach provides:

✅ **Type Safety** - Compile-time query validation  
✅ **Readability** - Self-documenting query structure  
✅ **IDE Support** - Auto-completion and method discovery  
✅ **Composability** - Reusable query fragments  
✅ **Maintainability** - Easy to modify and extend queries  

This gRPC-based architecture provides a modern, efficient, and developer-friendly interface for interacting with OxideDB across multiple programming languages and platforms.
