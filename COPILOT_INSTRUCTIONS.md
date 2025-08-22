# CortexDB Client Library SDK - Copilot Instructions

## Overview
Create comprehensive client libraries (SDKs) for connecting to CortexDB API from external applications. Support multiple programming languages with consistent APIs, proper error handling, and comprehensive documentation.

## API Endpoints Documentation

### Base URL Structure
```
http://localhost:11597/api/v1
```

### Authentication
All API requests require JWT authentication via `Authorization: Bearer <token>` header.

### Core Endpoints

#### 1. Authentication
```http
POST /auth/login
Content-Type: application/json

{
  "username": "string",
  "password": "string"
}

Response:
{
  "token": "jwt_token_string",
  "user_id": "uuid",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

#### 2. Query Execution
```http
POST /query
Authorization: Bearer <token>
ns: my_namespace
db: my_database
Content-Type: application/json

{
  "query": "SELECT * FROM users",
  "mode": "sql"  // "sql" or "ai"
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

## Client Library Architecture

### 1. Rust Client Library

```rust
// cortexdb-client/src/lib.rs
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct QueryResponse {
    pub success: bool,
    pub data: serde_json::Value,
    pub execution_time_ms: u64,
    pub rows_affected: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
enum QueryMode {
    Sql,
    Ai,
}

impl QueryMode {
    fn as_str(&self) -> &'static str {
        match self {
            QueryMode::Sql => "sql",
            QueryMode::Ai => "ai",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CortexDBError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("Query failed: {0}")]
    QueryError(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, CortexDBError>;

#[derive(Debug, Clone)]
pub struct CortexDB {
    client: Client,
    base_url: String,
    timeout: Duration,
    token: Option<String>,
    current_namespace: Option<String>,
    current_database: Option<String>,
    current_mode: QueryMode,
}

impl CortexDB {
    pub fn new() -> Self {
        Self::with_url("http://localhost:11597/api/v1")
    }

    pub fn with_url(base_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into(),
            timeout: Duration::from_secs(30),
            token: None,
            current_namespace: None,
            current_database: None,
            current_mode: QueryMode::Sql,
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn authenticate(mut self, username: &str, password: &str) -> Result<Self> {
        let request = serde_json::json!({
            "username": username,
            "password": password
        });

        let response = timeout(
            self.timeout,
            self.client
                .post(&format!("{}/auth/login", self.base_url))
                .json(&request)
                .send()
        ).await
        .map_err(|_| CortexDBError::Timeout("Authentication request timed out".to_string()))?
        .map_err(CortexDBError::HttpError)?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(CortexDBError::AuthError(error_text));
        }

        let login_response: LoginResponse = response.json().await?;
        self.token = Some(login_response.token);
        Ok(self)
    }

    pub fn use_db(mut self, namespace: &str, database: &str) -> Self {
        self.current_namespace = Some(namespace.to_string());
        self.current_database = Some(database.to_string());
        self
    }

    pub fn set(mut self, mode: &str) -> Result<Self> {
        self.current_mode = match mode {
            "sql" => QueryMode::Sql,
            "ai" => QueryMode::Ai,
            _ => return Err(CortexDBError::ConfigError(format!("Invalid mode: {}", mode))),
        };
        Ok(self)
    }

    pub async fn query(&self, query_string: &str) -> Result<QueryResponse> {
        let token = self.token.as_ref()
            .ok_or_else(|| CortexDBError::AuthError("Not authenticated".to_string()))?;

        let namespace = self.current_namespace.as_ref()
            .ok_or_else(|| CortexDBError::ConfigError("Namespace not set".to_string()))?;

        let database = self.current_database.as_ref()
            .ok_or_else(|| CortexDBError::ConfigError("Database not set".to_string()))?;

        let request = serde_json::json!({
            "query": query_string,
            "mode": self.current_mode.as_str()
        });

        let response = timeout(
            self.timeout,
            self.client
                .post(&format!("{}/query", self.base_url))
                .header("Authorization", format!("Bearer {}", token))
                .header("ns", namespace)
                .header("db", database)
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

    pub fn database(&self) -> Option<&str> {
        self.current_database.as_deref()
    }

    pub fn mode(&self) -> &str {
        self.current_mode.as_str()
    }

    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
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
            "mode": self._mode.value
        }

        headers = {
            "Authorization": f"Bearer {self._token}",
            "ns": self._namespace,
            "db": self._database
        }

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
          'ns': this.currentNamespace,
          'db': this.currentDatabase,
        },
        body: JSON.stringify({
          query: queryString,
          mode: this.currentMode,
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
        "query": queryString,
        "mode":  string(c.currentMode),
    }

    var resp QueryResponse
    err := c.makeRequestWithHeaders(ctx, "POST", "/query", reqBody, &resp, true, map[string]string{
        "ns": c.currentNamespace,
        "db": c.currentDatabase,
    })
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

func (c *CortexDB) makeRequestWithHeaders(ctx context.Context, method, path string, reqBody interface{}, respBody interface{}, requireAuth bool, customHeaders map[string]string) error {
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

    // Add custom headers
    for key, value := range customHeaders {
        req.Header.Set(key, value)
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

## Package Structure

### Rust Crate
```
cortexdb-client/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── client.rs
│   ├── types.rs
│   └── error.rs
├── examples/
│   └── basic_usage.rs
└── README.md
```

### Python Package
```
cortexdb-client/
├── setup.py
├── cortexdb_client/
│   ├── __init__.py
│   ├── client.py
│   ├── types.py
│   └── exceptions.py
├── examples/
│   └── basic_usage.py
└── README.md
```

### JavaScript/TypeScript Package
```
cortexdb-client/
├── package.json
├── src/
│   ├── index.ts
│   ├── client.ts
│   └── types.ts
├── examples/
│   ├── basic_usage.js
│   └── basic_usage.ts
└── README.md
```

### Go Module
```
cortexdb-go/
├── go.mod
├── client.go
├── types.go
├── examples/
│   └── main.go
└── README.md
```

## Documentation Requirements

### 1. API Reference
- Complete endpoint documentation
- Request/response schemas
- Error codes and handling
- Authentication flow

### 2. SDK Documentation
- Installation instructions
- Quick start guide
- Complete API reference
- Code examples for common use cases
- Error handling patterns

### 3. Examples
- Basic CRUD operations
- Authentication flow
- SQL vs AI query modes
- Error handling
- Connection pooling (where applicable)
- Async/await patterns

## Testing Strategy

### Unit Tests
- Request/response serialization
- Error handling
- Authentication flow
- Timeout handling

### Integration Tests
- End-to-end API communication
- Authentication scenarios
- Query execution
- Error scenarios

### Example Test (Rust)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_login_success() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": "test_token",
                "user_id": "test_user_id",
                "expires_at": "2024-12-31T23:59:59Z"
            })))
            .mount(&mock_server)
            .await;

        let mut client = CortexDBClient::new(mock_server.uri());
        let result = client.login("test_user", "test_pass").await;
        
        assert!(result.is_ok());
        assert_eq!(client.token, Some("test_token".to_string()));
    }
}
```

## Publishing

### Rust (crates.io)
```toml
[package]
name = "cortexdb-client"
version = "0.1.0"
description = "Official Rust client for CortexDB"
license = "MIT"
repository = "https://github.com/your-org/cortexdb-client-rust"
```

### Python (PyPI)
```python
setup(
    name="cortexdb-client",
    version="0.1.0",
    description="Official Python client for CortexDB",
    author="Your Organization",
    url="https://github.com/your-org/cortexdb-client-python",
    packages=find_packages(),
    install_requires=["aiohttp>=3.8.0"],
)
```

### JavaScript (npm)
```json
{
  "name": "cortexdb-client",
  "version": "0.1.0",
  "description": "Official JavaScript/TypeScript client for CortexDB",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "repository": "https://github.com/your-org/cortexdb-client-js"
}
```

### Go (go.mod)
```go
module github.com/your-org/cortexdb-client-go

go 1.19

require (
    // dependencies
)
```

## Benefits

✅ **Multi-language Support** - Rust, Python, JavaScript, Go clients  
✅ **Consistent API** - Same patterns across all languages  
✅ **Type Safety** - Full type definitions where supported  
✅ **Async Support** - Native async/await patterns  
✅ **Error Handling** - Comprehensive error types and handling  
✅ **Documentation** - Complete API docs and examples  
✅ **Testing** - Unit and integration test coverage  
✅ **Easy Distribution** - Published to package registries  

This client library architecture provides a professional, easy-to-use interface for developers to integrate with CortexDB from any application stack.
