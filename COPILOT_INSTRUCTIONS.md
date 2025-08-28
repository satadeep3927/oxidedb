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

<<<<<<< HEAD
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
=======
#### Query Messages
```protobuf
message QueryRequest {
  string token = 1;
  string query = 2;
  QueryMode mode = 3;
  string namespace = 4;
  string database = 5;
>>>>>>> 8d1390ea25de9b9f8dd6fc7f7d2f3a1adda86bdf
}

message QueryResponse {
  bool success = 1;
  oneof data {
    google.protobuf.Struct structured_data = 2;
    google.protobuf.Any any_data = 3;
  }
  string error = 4;
  uint64 execution_time_ms = 5;
  uint64 rows_affected = 6;
}

enum QueryMode {
  SQL = 0;
  AI = 1;
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

        let request = Request::new(QueryRequest {
            token: token.clone(),
            query: query.to_string(),
            mode: mode as i32,
            namespace: namespace.clone(),
            database: database.clone(),
        });

        let response = self.client.execute_query(request).await?;
        let query_response = response.into_inner();

        if !query_response.success {
            return Err(OxideDbError::Query(query_response.error));
        }

        Ok(query_response)
    }

    fn extract_data_array(&self, response: QueryResponse) -> Result<Vec<Value>, OxideDbError> {
        // Convert protobuf response to JSON values
        // Implementation depends on the specific data format
        Ok(vec![]) // Placeholder implementation
    }
}

// Knex-style query builder
#[derive(Debug)]
pub struct QueryBuilder {
    db: OxideDb,
    table_name: String,
    query_type: QueryType,
    select_columns: Vec<String>,
    where_conditions: Vec<WhereCondition>,
    joins: Vec<JoinClause>,
    order_clauses: Vec<OrderClause>,
    group_columns: Vec<String>,
    having_conditions: Vec<WhereCondition>,
    limit_count: Option<u64>,
    offset_count: Option<u64>,
    insert_values: Option<Value>,
    update_values: Option<HashMap<String, Value>>,
}

#[derive(Debug)]
enum QueryType {
    Select,
    Insert,
    Update,
    Delete,
}

#[derive(Debug)]
struct WhereCondition {
    column: String,
    operator: String,
    value: Value,
    boolean: String, // AND, OR
}

#[derive(Debug)]
struct JoinClause {
    table: String,
    join_type: String,
    condition: String,
}

#[derive(Debug)]
struct OrderClause {
    column: String,
    direction: String,
}

impl QueryBuilder {
    fn new(db: OxideDb, table: &str) -> Self {
        Self {
            db,
            table_name: table.to_string(),
            query_type: QueryType::Select,
            select_columns: vec!["*".to_string()],
            where_conditions: Vec::new(),
            joins: Vec::new(),
            order_clauses: Vec::new(),
            group_columns: Vec::new(),
            having_conditions: Vec::new(),
            limit_count: None,
            offset_count: None,
            insert_values: None,
            update_values: None,
        }
    }

    // SELECT operations
    pub fn select<T: ToString>(mut self, columns: &[T]) -> Self {
        self.query_type = QueryType::Select;
        self.select_columns = columns.iter().map(|c| c.to_string()).collect();
        self
    }

    // WHERE operations - Knex style
    pub fn where_<T: Into<Value>>(mut self, column: &str, operator: &str, value: T) -> Self {
        self.where_conditions.push(WhereCondition {
            column: column.to_string(),
            operator: operator.to_string(),
            value: value.into(),
            boolean: "AND".to_string(),
        });
        self
    }

    // Convenient where methods
    pub fn where_eq<T: Into<Value>>(self, column: &str, value: T) -> Self {
        self.where_(column, "=", value)
    }

    pub fn where_ne<T: Into<Value>>(self, column: &str, value: T) -> Self {
        self.where_(column, "!=", value)
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

    pub fn where_in<T: Into<Value>>(mut self, column: &str, values: &[T]) -> Self {
        let array_val = Value::Array(values.iter().map(|v| v.into()).collect());
        self.where_conditions.push(WhereCondition {
            column: column.to_string(),
            operator: "IN".to_string(),
            value: array_val,
            boolean: "AND".to_string(),
        });
        self
    }

    pub fn where_not_in<T: Into<Value>>(mut self, column: &str, values: &[T]) -> Self {
        let array_val = Value::Array(values.iter().map(|v| v.into()).collect());
        self.where_conditions.push(WhereCondition {
            column: column.to_string(),
            operator: "NOT IN".to_string(),
            value: array_val,
            boolean: "AND".to_string(),
        });
        self
    }

    pub fn where_null(self, column: &str) -> Self {
        self.where_(column, "IS", Value::Null)
    }

    pub fn where_not_null(self, column: &str) -> Self {
        self.where_(column, "IS NOT", Value::Null)
    }

    pub fn where_between<T: Into<Value>>(mut self, column: &str, min: T, max: T) -> Self {
        self.where_conditions.push(WhereCondition {
            column: column.to_string(),
            operator: "BETWEEN".to_string(),
            value: Value::Array(vec![min.into(), max.into()]),
            boolean: "AND".to_string(),
        });
        self
    }

    // OR WHERE operations
    pub fn or_where<T: Into<Value>>(mut self, column: &str, operator: &str, value: T) -> Self {
        self.where_conditions.push(WhereCondition {
            column: column.to_string(),
            operator: operator.to_string(),
            value: value.into(),
            boolean: "OR".to_string(),
        });
        self
    }

    pub fn or_where_eq<T: Into<Value>>(self, column: &str, value: T) -> Self {
        self.or_where(column, "=", value)
    }

    // JOIN operations
    pub fn join(mut self, table: &str, condition: &str) -> Self {
        self.joins.push(JoinClause {
            table: table.to_string(),
            join_type: "INNER".to_string(),
            condition: condition.to_string(),
        });
        self
    }

    pub fn left_join(mut self, table: &str, condition: &str) -> Self {
        self.joins.push(JoinClause {
            table: table.to_string(),
            join_type: "LEFT".to_string(),
            condition: condition.to_string(),
        });
        self
    }

    pub fn right_join(mut self, table: &str, condition: &str) -> Self {
        self.joins.push(JoinClause {
            table: table.to_string(),
            join_type: "RIGHT".to_string(),
            condition: condition.to_string(),
        });
        self
    }

    pub fn full_outer_join(mut self, table: &str, condition: &str) -> Self {
        self.joins.push(JoinClause {
            table: table.to_string(),
            join_type: "FULL OUTER".to_string(),
            condition: condition.to_string(),
        });
        self
    }

    // ORDER BY operations
    pub fn order_by(mut self, column: &str, direction: &str) -> Self {
        self.order_clauses.push(OrderClause {
            column: column.to_string(),
            direction: direction.to_uppercase(),
        });
        self
    }

    pub fn order_by_asc(self, column: &str) -> Self {
        self.order_by(column, "ASC")
    }

    pub fn order_by_desc(self, column: &str) -> Self {
        self.order_by(column, "DESC")
    }

    // LIMIT and OFFSET
    pub fn limit(mut self, count: u64) -> Self {
        self.limit_count = Some(count);
        self
    }

    pub fn offset(mut self, count: u64) -> Self {
        self.offset_count = Some(count);
        self
    }

    // GROUP BY and HAVING
    pub fn group_by<T: ToString>(mut self, columns: &[T]) -> Self {
        self.group_columns = columns.iter().map(|c| c.to_string()).collect();
        self
    }

    pub fn having<T: Into<Value>>(mut self, column: &str, operator: &str, value: T) -> Self {
        self.having_conditions.push(WhereCondition {
            column: column.to_string(),
            operator: operator.to_string(),
            value: value.into(),
            boolean: "AND".to_string(),
        });
        self
    }

    // INSERT operations
    pub fn insert<T: Into<Value>>(mut self, data: T) -> Self {
        self.query_type = QueryType::Insert;
        self.insert_values = Some(data.into());
        self
    }

    // UPDATE operations
    pub fn update(mut self, data: HashMap<String, Value>) -> Self {
        self.query_type = QueryType::Update;
        self.update_values = Some(data);
        self
    }

    // DELETE operations
    pub fn delete(mut self) -> Self {
        self.query_type = QueryType::Delete;
        self
    }

    // Knex shorthand for delete
    pub fn del(self) -> Self {
        self.delete()
    }

    // Aggregation methods
    pub async fn count(mut self, column: &str) -> Result<u64, OxideDbError> {
        self.select_columns = vec![format!("COUNT({}) as count", column)];
        let results = self.execute().await?;
        Ok(results.first()
            .and_then(|r| r.get("count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0))
    }

    pub async fn sum(mut self, column: &str) -> Result<f64, OxideDbError> {
        self.select_columns = vec![format!("SUM({}) as sum", column)];
        let results = self.execute().await?;
        Ok(results.first()
            .and_then(|r| r.get("sum"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0))
    }

    pub async fn avg(mut self, column: &str) -> Result<f64, OxideDbError> {
        self.select_columns = vec![format!("AVG({}) as avg", column)];
        let results = self.execute().await?;
        Ok(results.first()
            .and_then(|r| r.get("avg"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0))
    }

    pub async fn max(mut self, column: &str) -> Result<Option<Value>, OxideDbError> {
        self.select_columns = vec![format!("MAX({}) as max", column)];
        let results = self.execute().await?;
        Ok(results.first()
            .and_then(|r| r.get("max"))
            .cloned())
    }

    pub async fn min(mut self, column: &str) -> Result<Option<Value>, OxideDbError> {
        self.select_columns = vec![format!("MIN({}) as min", column)];
        let results = self.execute().await?;
        Ok(results.first()
            .and_then(|r| r.get("min"))
            .cloned())
    }

    // Execution methods
    pub async fn execute(self) -> Result<Vec<Value>, OxideDbError> {
        let sql = self.build_sql()?;
        let mut db = self.db;
        let result = db.execute_sql(&sql).await?;
        db.extract_data_array(result)
    }

    pub async fn first(mut self) -> Result<Option<Value>, OxideDbError> {
        self.limit_count = Some(1);
        let mut results = self.execute().await?;
        Ok(results.into_iter().next())
    }

    // Internal SQL building
    fn build_sql(&self) -> Result<String, OxideDbError> {
        match self.query_type {
            QueryType::Select => self.build_select_sql(),
            QueryType::Insert => self.build_insert_sql(),
            QueryType::Update => self.build_update_sql(),
            QueryType::Delete => self.build_delete_sql(),
        }
    }

    fn build_select_sql(&self) -> Result<String, OxideDbError> {
        let mut sql = format!("SELECT {} FROM {}", 
            self.select_columns.join(", "), 
            self.table_name);

        // Add JOINs
        for join in &self.joins {
            sql.push_str(&format!(" {} JOIN {} ON {}", 
                join.join_type, join.table, join.condition));
        }

        // Add WHERE conditions
        if !self.where_conditions.is_empty() {
            sql.push_str(" WHERE ");
            for (i, condition) in self.where_conditions.iter().enumerate() {
                if i > 0 {
                    sql.push_str(&format!(" {} ", condition.boolean));
                }
                sql.push_str(&format!("{} {} {}", 
                    condition.column, 
                    condition.operator, 
                    self.format_value(&condition.value)));
            }
        }

        // Add GROUP BY
        if !self.group_columns.is_empty() {
            sql.push_str(&format!(" GROUP BY {}", self.group_columns.join(", ")));
        }

        // Add HAVING
        if !self.having_conditions.is_empty() {
            sql.push_str(" HAVING ");
            for (i, condition) in self.having_conditions.iter().enumerate() {
                if i > 0 {
                    sql.push_str(&format!(" {} ", condition.boolean));
                }
                sql.push_str(&format!("{} {} {}", 
                    condition.column, 
                    condition.operator, 
                    self.format_value(&condition.value)));
            }
        }

        // Add ORDER BY
        if !self.order_clauses.is_empty() {
            let order_parts: Vec<String> = self.order_clauses.iter()
                .map(|o| format!("{} {}", o.column, o.direction))
                .collect();
            sql.push_str(&format!(" ORDER BY {}", order_parts.join(", ")));
        }

        // Add LIMIT and OFFSET
        if let Some(limit) = self.limit_count {
            sql.push_str(&format!(" LIMIT {}", limit));
        }
        if let Some(offset) = self.offset_count {
            sql.push_str(&format!(" OFFSET {}", offset));
        }

        Ok(sql)
    }

    fn build_insert_sql(&self) -> Result<String, OxideDbError> {
        if let Some(data) = &self.insert_values {
            match data {
                Value::Object(map) => {
                    let columns: Vec<String> = map.keys().cloned().collect();
                    let values: Vec<String> = map.values()
                        .map(|v| self.format_value(v))
                        .collect();
                    Ok(format!("INSERT INTO {} ({}) VALUES ({})",
                        self.table_name,
                        columns.join(", "),
                        values.join(", ")))
                },
                Value::Array(arr) => {
                    // Batch insert
                    if let Some(Value::Object(first)) = arr.first() {
                        let columns: Vec<String> = first.keys().cloned().collect();
                        let mut all_values = Vec::new();
                        
                        for item in arr {
                            if let Value::Object(obj) = item {
                                let values: Vec<String> = columns.iter()
                                    .map(|col| self.format_value(obj.get(col).unwrap_or(&Value::Null)))
                                    .collect();
                                all_values.push(format!("({})", values.join(", ")));
                            }
                        }
                        
                        Ok(format!("INSERT INTO {} ({}) VALUES {}",
                            self.table_name,
                            columns.join(", "),
                            all_values.join(", ")))
                    } else {
                        Err(OxideDbError::Config("Invalid insert data format".to_string()))
                    }
                },
                _ => Err(OxideDbError::Config("Insert data must be object or array".to_string()))
            }
        } else {
            Err(OxideDbError::Config("No insert data provided".to_string()))
        }
    }

    fn build_update_sql(&self) -> Result<String, OxideDbError> {
        if let Some(data) = &self.update_values {
            let updates: Vec<String> = data.iter()
                .map(|(k, v)| format!("{} = {}", k, self.format_value(v)))
                .collect();

            let mut sql = format!("UPDATE {} SET {}", 
                self.table_name, 
                updates.join(", "));

            // Add WHERE conditions
            if !self.where_conditions.is_empty() {
                sql.push_str(" WHERE ");
                for (i, condition) in self.where_conditions.iter().enumerate() {
                    if i > 0 {
                        sql.push_str(&format!(" {} ", condition.boolean));
                    }
                    sql.push_str(&format!("{} {} {}", 
                        condition.column, 
                        condition.operator, 
                        self.format_value(&condition.value)));
                }
            }

            Ok(sql)
        } else {
            Err(OxideDbError::Config("No update data provided".to_string()))
        }
    }

    fn build_delete_sql(&self) -> Result<String, OxideDbError> {
        let mut sql = format!("DELETE FROM {}", self.table_name);

        // Add WHERE conditions
        if !self.where_conditions.is_empty() {
            sql.push_str(" WHERE ");
            for (i, condition) in self.where_conditions.iter().enumerate() {
                if i > 0 {
                    sql.push_str(&format!(" {} ", condition.boolean));
                }
                sql.push_str(&format!("{} {} {}", 
                    condition.column, 
                    condition.operator, 
                    self.format_value(&condition.value)));
            }
        }

        Ok(sql)
    }

    fn format_value(&self, value: &Value) -> String {
        match value {
            Value::String(s) => format!("'{}'", s.replace("'", "''")),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "NULL".to_string(),
            Value::Array(arr) => {
                let formatted: Vec<String> = arr.iter()
                    .map(|v| self.format_value(v))
                    .collect();
                if arr.len() == 2 { // For BETWEEN
                    format!("{} AND {}", formatted[0], formatted[1])
                } else {
                    format!("({})", formatted.join(", "))
                }
            },
            _ => format!("'{}'", value.to_string()),
        }
    }
}

// Schema builder for DDL operations
pub struct SchemaBuilder {
    db: OxideDb,
}

impl SchemaBuilder {
    fn new(db: OxideDb) -> Self {
        Self { db }
    }

    pub fn create_table<F>(&self, table: &str, callback: F) -> TableBuilder
    where
        F: FnOnce(&mut TableBuilder),
    {
        let mut builder = TableBuilder::new(self.db.clone(), table, "CREATE");
        callback(&mut builder);
        builder
    }

    pub fn alter_table<F>(&self, table: &str, callback: F) -> TableBuilder
    where
        F: FnOnce(&mut TableBuilder),
    {
        let mut builder = TableBuilder::new(self.db.clone(), table, "ALTER");
        callback(&mut builder);
        builder
    }

    pub async fn drop_table(&self, table: &str) -> Result<(), OxideDbError> {
        let sql = format!("DROP TABLE {}", table);
        let mut db = self.db.clone();
        db.execute_sql(&sql).await?;
        Ok(())
    }

    pub async fn has_table(&self, table: &str) -> Result<bool, OxideDbError> {
        let sql = format!("SELECT name FROM sqlite_master WHERE type='table' AND name='{}'", table);
        let mut db = self.db.clone();
        let result = db.execute_sql(&sql).await?;
        let data = db.extract_data_array(result)?;
        Ok(!data.is_empty())
    }
}

// Table builder for schema operations  
pub struct TableBuilder {
    db: OxideDb,
    table_name: String,
    operation: String,
    column_definitions: Vec<String>,
}

impl TableBuilder {
    fn new(db: OxideDb, table: &str, operation: &str) -> Self {
        Self {
            db,
            table_name: table.to_string(),
            operation: operation.to_string(),
            column_definitions: Vec::new(),
        }
    }

    pub fn increments(&mut self, column: &str) -> &mut Self {
        self.column_definitions.push(format!("{} INTEGER PRIMARY KEY AUTOINCREMENT", column));
        self
    }

    pub fn string(&mut self, column: &str) -> ColumnBuilder {
        ColumnBuilder::new(self, column, "TEXT")
    }

    pub fn integer(&mut self, column: &str) -> ColumnBuilder {
        ColumnBuilder::new(self, column, "INTEGER")
    }

    pub fn text(&mut self, column: &str) -> ColumnBuilder {
        ColumnBuilder::new(self, column, "TEXT")
    }

    pub fn boolean(&mut self, column: &str) -> ColumnBuilder {
        ColumnBuilder::new(self, column, "BOOLEAN")
    }

    pub fn float(&mut self, column: &str) -> ColumnBuilder {
        ColumnBuilder::new(self, column, "REAL")
    }

    pub fn decimal(&mut self, column: &str, precision: u8, scale: u8) -> ColumnBuilder {
        ColumnBuilder::new(self, column, &format!("DECIMAL({}, {})", precision, scale))
    }

    pub fn timestamps(&mut self) -> &mut Self {
        self.column_definitions.push("created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP".to_string());
        self.column_definitions.push("updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP".to_string());
        self
    }

    fn add_column_definition(&mut self, definition: String) {
        self.column_definitions.push(definition);
    }

    pub async fn execute(&self) -> Result<(), OxideDbError> {
        let sql = match self.operation.as_str() {
            "CREATE" => format!("CREATE TABLE {} ({})", 
                self.table_name, 
                self.column_definitions.join(", ")),
            "ALTER" => format!("ALTER TABLE {} ADD COLUMN {}", 
                self.table_name, 
                self.column_definitions.join(", ADD COLUMN ")),
            _ => return Err(OxideDbError::Config("Invalid table operation".to_string())),
        };

        let mut db = self.db.clone();
        db.execute_sql(&sql).await?;
        Ok(())
    }
}

// Column builder for fluent column definitions
pub struct ColumnBuilder<'a> {
    table_builder: &'a mut TableBuilder,
    column_name: String,
    column_type: String,
    modifiers: Vec<String>,
}

impl<'a> ColumnBuilder<'a> {
    fn new(table_builder: &'a mut TableBuilder, column: &str, col_type: &str) -> Self {
        Self {
            table_builder,
            column_name: column.to_string(),
            column_type: col_type.to_string(),
            modifiers: Vec::new(),
        }
    }

    pub fn not_nullable(mut self) -> Self {
        self.modifiers.push("NOT NULL".to_string());
        self
    }

    pub fn nullable(mut self) -> Self {
        // nullable is default, no modifier needed
        self
    }

    pub fn unique(mut self) -> Self {
        self.modifiers.push("UNIQUE".to_string());
        self
    }

    pub fn default_to<T: ToString>(mut self, value: T) -> Self {
        self.modifiers.push(format!("DEFAULT {}", value.to_string()));
        self
    }

    pub fn references(&mut self, column: &str) -> &mut TableBuilder {
        self.modifiers.push(format!("REFERENCES {}", column));
        let definition = format!("{} {} {}", 
            self.column_name, 
            self.column_type, 
            self.modifiers.join(" "));
        self.table_builder.add_column_definition(definition);
        self.table_builder
    }
}

impl<'a> Drop for ColumnBuilder<'a> {
    fn drop(&mut self) {
        let definition = format!("{} {} {}", 
            self.column_name, 
            self.column_type, 
            self.modifiers.join(" ")).trim().to_string();
        self.table_builder.add_column_definition(definition);
    }
}

// AI query builder
pub struct AiBuilder {
    db: OxideDb,
}

impl AiBuilder {
    fn new(db: OxideDb) -> Self {
        Self { db }
    }

    pub async fn query(&self, natural_query: &str) -> Result<Vec<Value>, OxideDbError> {
        let mut db = self.db.clone();
        let result = db.execute_query(natural_query, QueryMode::Ai).await?;
        db.extract_data_array(result)
    }

    pub async fn explain(&self, query_result: &[Value]) -> Result<String, OxideDbError> {
        let explanation_query = format!("Explain this data: {:?}", query_result);
        let results = self.query(&explanation_query).await?;
        Ok(serde_json::to_string(&results)?)
    }

    pub async fn suggest(&self, table: &str, operation: &str) -> Result<Vec<String>, OxideDbError> {
        let suggestion_query = format!("Suggest {} operations for table {}", operation, table);
        let results = self.query(&suggestion_query).await?;
        // Convert results to suggestions
        Ok(vec!["Suggested operation".to_string()]) // Placeholder
    }
}

// Usage examples - Knex style
async fn example_knex_usage() -> Result<(), OxideDbError> {
    // Connect and authenticate
    let db = OxideDb::connect("127.0.0.1:11597")
        .await?
        .authenticate("admin", "password")
        .await?
        .use_db("test", "test");

    // Create table - Knex style
    db.schema()
        .create_table("users", |table| {
            table.increments("id");
            table.string("name").not_nullable();
            table.string("email").unique();
            table.integer("age").nullable();
            table.timestamps();
        })
        .execute()
        .await?;

    // Insert data - Knex style
    db.table("users")
        .insert(serde_json::json!({
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30
        }))
        .execute()
        .await?;

    // Batch insert - Knex style
    db.table("users")
        .insert(serde_json::json!([
            {"name": "Alice", "email": "alice@example.com", "age": 25},
            {"name": "Bob", "email": "bob@example.com", "age": 35}
        ]))
        .execute()
        .await?;

    // Select data - Knex style
    let users = db.table("users")
        .select(&["id", "name", "email"])
        .where_("age", ">", 18)
        .order_by_desc("created_at")
        .limit(10)
        .execute()
        .await?;

    // Complex query with joins - Knex style
    let user_profiles = db.table("users")
        .select(&["users.name", "profiles.bio", "users.email"])
        .left_join("profiles", "users.id = profiles.user_id")
        .where_("users.active", "=", true)
        .where_in("users.role", &["admin", "user"])
        .order_by_asc("users.name")
        .execute()
        .await?;

    // Update data - Knex style
    db.table("users")
        .where_eq("id", 1)
        .update(HashMap::from([
            ("name".to_string(), "John Smith".into()),
            ("updated_at".to_string(), "NOW()".into()),
        ]))
        .execute()
        .await?;

    // Delete data - Knex style
    db.table("users")
        .where_("last_login", "<", "2023-01-01")
        .del()
        .execute()
        .await?;

    // Aggregations - Knex style
    let user_count = db.table("users").count("*").await?;
    let avg_age = db.table("users").avg("age").await?;
    let total_posts = db.table("posts").sum("view_count").await?;

    // Group by with having - Knex style
    let stats = db.table("users")
        .select(&["status", "COUNT(*) as count"])
        .group_by(&["status"])
        .having("count", ">", 5)
        .execute()
        .await?;

    // AI queries
    let ai_results = db.ai()
        .query("Show me all users who joined this month")
        .await?;

    println!("Users: {:?}", users);
    println!("User count: {}", user_count);
    println!("AI results: {:?}", ai_results);

    Ok(())
}
```
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

    /// CREATE: Insert single record
    pub async fn insert(&mut self, table: &str, data: &Value) -> Result<u64, OxideDbError> {
        let sql = self.build_insert_sql(table, data)?;
        let result = self.execute_sql(&sql).await?;
        Ok(result.rows_affected)
    }

    /// CREATE: Insert multiple records
    pub async fn insert_batch(&mut self, table: &str, data: &[Value]) -> Result<u64, OxideDbError> {
        let mut total_affected = 0;
        for record in data {
            total_affected += self.insert(table, record).await?;
        }
        Ok(total_affected)
    }

    /// CREATE: Create table with schema
    pub async fn create_table(&mut self, table: &str, schema: &HashMap<String, String>) -> Result<(), OxideDbError> {
        let sql = self.build_create_table_sql(table, schema);
        self.execute_sql(&sql).await?;
        Ok(())
    }

    /// READ: Select records with conditions
    pub async fn select(&mut self, table: &str, conditions: Option<&str>) -> Result<Vec<Value>, OxideDbError> {
        let sql = match conditions {
            Some(cond) => format!("SELECT * FROM {} WHERE {}", table, cond),
            None => format!("SELECT * FROM {}", table),
        };
        let result = self.execute_sql(&sql).await?;
        self.extract_data_array(result)
    }

    /// READ: Find single record by ID
    pub async fn find_by_id(&mut self, table: &str, id: &Value) -> Result<Option<Value>, OxideDbError> {
        let condition = format!("id = {}", self.format_value(id));
        let mut results = self.select(table, Some(&condition)).await?;
        Ok(results.pop())
    }

    /// READ: Count records
    pub async fn count(&mut self, table: &str, conditions: Option<&str>) -> Result<u64, OxideDbError> {
        let sql = match conditions {
            Some(cond) => format!("SELECT COUNT(*) as count FROM {} WHERE {}", table, cond),
            None => format!("SELECT COUNT(*) as count FROM {}", table),
        };
        let result = self.execute_sql(&sql).await?;
        let data = self.extract_data_array(result)?;
        Ok(data[0]["count"].as_u64().unwrap_or(0))
    }

    /// UPDATE: Update single record by ID
    pub async fn update(&mut self, table: &str, id: &Value, data: &Value) -> Result<u64, OxideDbError> {
        let sql = self.build_update_sql(table, id, data)?;
        let result = self.execute_sql(&sql).await?;
        Ok(result.rows_affected)
    }

    /// UPDATE: Update records matching conditions
    pub async fn update_where(&mut self, table: &str, conditions: &str, data: &Value) -> Result<u64, OxideDbError> {
        let sql = self.build_update_where_sql(table, conditions, data)?;
        let result = self.execute_sql(&sql).await?;
        Ok(result.rows_affected)
    }

    /// DELETE: Delete single record by ID
    pub async fn delete(&mut self, table: &str, id: &Value) -> Result<u64, OxideDbError> {
        let condition = format!("id = {}", self.format_value(id));
        self.delete_where(table, &condition).await
    }

    /// DELETE: Delete records matching conditions
    pub async fn delete_where(&mut self, table: &str, conditions: &str) -> Result<u64, OxideDbError> {
        let sql = format!("DELETE FROM {} WHERE {}", table, conditions);
        let result = self.execute_sql(&sql).await?;
        Ok(result.rows_affected)
    }

    /// AI: Execute natural language query
    pub async fn query_ai(&mut self, natural_query: &str) -> Result<Vec<Value>, OxideDbError> {
        let result = self.execute_query(natural_query, QueryMode::Ai).await?;
        self.extract_data_array(result)
    }

    /// Raw SQL execution
    pub async fn sql(&mut self, query: &str) -> Result<Vec<Value>, OxideDbError> {
        let result = self.execute_sql(query).await?;
        self.extract_data_array(result)
    }

    // Private helper methods
    async fn execute_sql(&mut self, query: &str) -> Result<QueryResponse, OxideDbError> {
        self.execute_query(query, QueryMode::Sql).await
    }

    async fn execute_query(&mut self, query: &str, mode: QueryMode) -> Result<QueryResponse, OxideDbError> {
        let token = self.token.as_ref().ok_or_else(|| OxideDbError::Auth("Not authenticated".to_string()))?;
        let namespace = self.namespace.as_ref().ok_or_else(|| OxideDbError::Config("Namespace not set".to_string()))?;
        let database = self.database.as_ref().ok_or_else(|| OxideDbError::Config("Database not set".to_string()))?;

        let request = Request::new(QueryRequest {
            token: token.clone(),
            query: query.to_string(),
            mode: mode as i32,
            namespace: namespace.clone(),
            database: database.clone(),
        });

        let response = self.client.execute_query(request).await?;
        let query_response = response.into_inner();

        if !query_response.success {
            return Err(OxideDbError::Query(query_response.error));
        }

        Ok(query_response)
    }

    fn extract_data_array(&self, response: QueryResponse) -> Result<Vec<Value>, OxideDbError> {
        match response.data {
            Some(data) => {
                // Convert protobuf Struct/Any to serde_json::Value
                // Implementation depends on the specific data format
                // This is a simplified version
                Ok(vec![serde_json::Value::Null]) // Placeholder
            }
            None => Ok(vec![]),
        }
    }

    fn build_insert_sql(&self, table: &str, data: &Value) -> Result<String, OxideDbError> {
        if let Value::Object(map) = data {
            let columns: Vec<String> = map.keys().cloned().collect();
            let values: Vec<String> = map.values().map(|v| self.format_value(v)).collect();
            Ok(format!(
                "INSERT INTO {} ({}) VALUES ({})",
                table,
                columns.join(", "),
                values.join(", ")
            ))
        } else {
            Err(OxideDbError::Config("Data must be an object".to_string()))
        }
    }

    fn build_update_sql(&self, table: &str, id: &Value, data: &Value) -> Result<String, OxideDbError> {
        if let Value::Object(map) = data {
            let updates: Vec<String> = map.iter()
                .map(|(k, v)| format!("{} = {}", k, self.format_value(v)))
                .collect();
            Ok(format!(
                "UPDATE {} SET {} WHERE id = {}",
                table,
                updates.join(", "),
                self.format_value(id)
            ))
        } else {
            Err(OxideDbError::Config("Data must be an object".to_string()))
        }
    }

    fn build_update_where_sql(&self, table: &str, conditions: &str, data: &Value) -> Result<String, OxideDbError> {
        if let Value::Object(map) = data {
            let updates: Vec<String> = map.iter()
                .map(|(k, v)| format!("{} = {}", k, self.format_value(v)))
                .collect();
            Ok(format!(
                "UPDATE {} SET {} WHERE {}",
                table,
                updates.join(", "),
                conditions
            ))
        } else {
            Err(OxideDbError::Config("Data must be an object".to_string()))
        }
    }

    fn build_create_table_sql(&self, table: &str, schema: &HashMap<String, String>) -> String {
        let columns: Vec<String> = schema.iter()
            .map(|(name, type_def)| format!("{} {}", name, type_def))
            .collect();
        format!("CREATE TABLE {} ({})", table, columns.join(", "))
    }

    fn format_value(&self, value: &Value) -> String {
        match value {
            Value::String(s) => format!("'{}'", s.replace("'", "''")),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "NULL".to_string(),
            _ => format!("'{}'", value.to_string()),
        }
### 2. Python Client Library

```python
# oxidedb_client/__init__.py
import asyncio
import grpc
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass

# Import generated protobuf classes
from . import oxidedb_pb2
from . import oxidedb_pb2_grpc

@dataclass
class OxideDbError(Exception):
    """Base exception for OxideDB client errors"""
    message: str

class OxideDb:
    """
    OxideDB gRPC client with abstraction methods
    
    Example:
        async with OxideDb.connect('127.0.0.1:11597') as db:
            await db.authenticate('user', 'pass')
            db.use_db('test', 'test')
            
            # CRUD operations
            user_id = await db.insert('users', {'name': 'John', 'email': 'john@example.com'})
            user = await db.find_by_id('users', user_id)
            await db.update('users', user_id, {'email': 'newemail@example.com'})
            await db.delete('users', user_id)
    """
    
    def __init__(self, channel: grpc.aio.Channel):
        self._channel = channel
        self._stub = oxidedb_pb2_grpc.OxideDbServiceStub(channel)
        self._token: Optional[str] = None
        self._namespace: Optional[str] = None
        self._database: Optional[str] = None

    @classmethod
    async def connect(cls, address: str) -> 'OxideDb':
        """Connect to OxideDB server"""
        channel = grpc.aio.insecure_channel(address)
        return cls(channel)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._channel.close()

    async def authenticate(self, username: str, password: str) -> 'OxideDb':
        """Authenticate with username and password"""
        request = oxidedb_pb2.LoginRequest(
            username=username,
            password=password
        )
        
        response = await self._stub.Login(request)
        
        if not response.success:
            raise OxideDbError(f"Authentication failed: {response.error}")
        
        self._token = response.token
        return self

    def use_db(self, namespace: str, database: str) -> 'OxideDb':
        """Select namespace and database"""
        self._namespace = namespace
        self._database = database
        return self

    # CREATE Operations
    async def insert(self, table: str, data: Dict[str, Any]) -> int:
        """Insert single record and return rows affected"""
        sql = self._build_insert_sql(table, data)
        result = await self._execute_sql(sql)
        return result.rows_affected

    async def insert_batch(self, table: str, data: List[Dict[str, Any]]) -> int:
        """Insert multiple records and return total rows affected"""
        total_affected = 0
        for record in data:
            total_affected += await self.insert(table, record)
        return total_affected

    async def create_table(self, table: str, schema: Dict[str, str]) -> None:
        """Create table with schema definition"""
        sql = self._build_create_table_sql(table, schema)
        await self._execute_sql(sql)

    # READ Operations
    async def select(self, table: str, conditions: Optional[str] = None, 
                    limit: Optional[int] = None, order_by: Optional[str] = None) -> List[Dict[str, Any]]:
        """Select records with optional conditions, limit, and ordering"""
        sql = f"SELECT * FROM {table}"
        if conditions:
            sql += f" WHERE {conditions}"
        if order_by:
            sql += f" ORDER BY {order_by}"
        if limit:
            sql += f" LIMIT {limit}"
        
        result = await self._execute_sql(sql)
        return self._extract_data_array(result)

    async def find_by_id(self, table: str, id_value: Any) -> Optional[Dict[str, Any]]:
        """Find single record by ID"""
        condition = f"id = {self._format_value(id_value)}"
        results = await self.select(table, condition, limit=1)
        return results[0] if results else None

    async def find_one(self, table: str, conditions: str) -> Optional[Dict[str, Any]]:
        """Find first record matching conditions"""
        results = await self.select(table, conditions, limit=1)
        return results[0] if results else None

    async def find_all(self, table: str, conditions: Optional[str] = None) -> List[Dict[str, Any]]:
        """Find all records matching conditions"""
        return await self.select(table, conditions)

    async def count(self, table: str, conditions: Optional[str] = None) -> int:
        """Count records matching conditions"""
        sql = f"SELECT COUNT(*) as count FROM {table}"
        if conditions:
            sql += f" WHERE {conditions}"
        
        result = await self._execute_sql(sql)
        data = self._extract_data_array(result)
        return data[0]['count'] if data else 0

    # UPDATE Operations
    async def update(self, table: str, id_value: Any, data: Dict[str, Any]) -> int:
        """Update single record by ID"""
        sql = self._build_update_sql(table, id_value, data)
        result = await self._execute_sql(sql)
        return result.rows_affected

    async def update_where(self, table: str, conditions: str, data: Dict[str, Any]) -> int:
        """Update records matching conditions"""
        sql = self._build_update_where_sql(table, conditions, data)
        result = await self._execute_sql(sql)
        return result.rows_affected

    async def upsert(self, table: str, id_value: Any, data: Dict[str, Any]) -> int:
        """Insert or update record (upsert)"""
        existing = await self.find_by_id(table, id_value)
        if existing:
            return await self.update(table, id_value, data)
        else:
            data['id'] = id_value
            return await self.insert(table, data)

    # DELETE Operations
    async def delete(self, table: str, id_value: Any) -> int:
        """Delete single record by ID"""
        condition = f"id = {self._format_value(id_value)}"
        return await self.delete_where(table, condition)

    async def delete_where(self, table: str, conditions: str) -> int:
        """Delete records matching conditions"""
        sql = f"DELETE FROM {table} WHERE {conditions}"
        result = await self._execute_sql(sql)
        return result.rows_affected

    async def drop_table(self, table: str) -> None:
        """Delete entire table"""
        sql = f"DROP TABLE {table}"
        await self._execute_sql(sql)

    # AI Operations
    async def query_ai(self, natural_query: str) -> List[Dict[str, Any]]:
        """Execute natural language query using AI"""
        result = await self._execute_query(natural_query, oxidedb_pb2.QueryMode.AI)
        return self._extract_data_array(result)

    async def explain_ai(self, query_result: List[Dict[str, Any]]) -> str:
        """Get AI explanation of query results"""
        ai_query = f"Explain this data: {query_result}"
        result = await self.query_ai(ai_query)
        return str(result)

    # Raw SQL Operations
    async def sql(self, query: str) -> List[Dict[str, Any]]:
        """Execute raw SQL query"""
        result = await self._execute_sql(query)
        return self._extract_data_array(result)

    # Private helper methods
    async def _execute_sql(self, query: str) -> oxidedb_pb2.QueryResponse:
        """Execute SQL query"""
        return await self._execute_query(query, oxidedb_pb2.QueryMode.SQL)

    async def _execute_query(self, query: str, mode: oxidedb_pb2.QueryMode) -> oxidedb_pb2.QueryResponse:
        """Execute query with specified mode"""
        if not self._token:
            raise OxideDbError("Not authenticated")
        if not self._namespace or not self._database:
            raise OxideDbError("Namespace and database must be set")

        request = oxidedb_pb2.QueryRequest(
            token=self._token,
            query=query,
            mode=mode,
            namespace=self._namespace,
            database=self._database
        )

        response = await self._stub.ExecuteQuery(request)
        
        if not response.success:
            raise OxideDbError(f"Query failed: {response.error}")
        
        return response

    def _extract_data_array(self, response: oxidedb_pb2.QueryResponse) -> List[Dict[str, Any]]:
        """Extract data array from response"""
        # Convert protobuf Struct to Python dict
        # Implementation depends on the specific data format
        if response.HasField('data'):
            # Handle structured_data or any_data
            return []  # Placeholder implementation
        return []

    def _build_insert_sql(self, table: str, data: Dict[str, Any]) -> str:
        """Build INSERT SQL statement"""
        columns = list(data.keys())
        values = [self._format_value(data[col]) for col in columns]
        return f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join(values)})"

    def _build_update_sql(self, table: str, id_value: Any, data: Dict[str, Any]) -> str:
        """Build UPDATE SQL statement"""
        updates = [f"{col} = {self._format_value(val)}" for col, val in data.items()]
        return f"UPDATE {table} SET {', '.join(updates)} WHERE id = {self._format_value(id_value)}"

    def _build_update_where_sql(self, table: str, conditions: str, data: Dict[str, Any]) -> str:
        """Build UPDATE SQL statement with WHERE conditions"""
        updates = [f"{col} = {self._format_value(val)}" for col, val in data.items()]
        return f"UPDATE {table} SET {', '.join(updates)} WHERE {conditions}"

    def _build_create_table_sql(self, table: str, schema: Dict[str, str]) -> str:
        """Build CREATE TABLE SQL statement"""
        columns = [f"{name} {type_def}" for name, type_def in schema.items()]
        return f"CREATE TABLE {table} ({', '.join(columns)})"

    def _format_value(self, value: Any) -> str:
        """Format value for SQL"""
        if isinstance(value, str):
            return f"'{value.replace('\'', '\'\'')}'"
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, bool):
            return str(value).lower()
        elif value is None:
            return 'NULL'
        else:
            return f"'{str(value)}'"

# Synchronous wrapper
class SyncOxideDb:
    """Synchronous wrapper for async OxideDb client"""
    
    def __init__(self, address: str):
        self._address = address
        self._loop = asyncio.new_event_loop()
        self._db = None

    def __enter__(self):
        self._db = self._loop.run_until_complete(OxideDb.connect(self._address))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._db:
            self._loop.run_until_complete(self._db._channel.close())
        self._loop.close()

    def authenticate(self, username: str, password: str):
        self._loop.run_until_complete(self._db.authenticate(username, password))
        return self

    def use_db(self, namespace: str, database: str):
        self._db.use_db(namespace, database)
        return self

    # Sync versions of all CRUD methods
    def insert(self, table: str, data: Dict[str, Any]) -> int:
        return self._loop.run_until_complete(self._db.insert(table, data))

    def select(self, table: str, conditions: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._loop.run_until_complete(self._db.select(table, conditions))

    def update(self, table: str, id_value: Any, data: Dict[str, Any]) -> int:
        return self._loop.run_until_complete(self._db.update(table, id_value, data))

    def delete(self, table: str, id_value: Any) -> int:
        return self._loop.run_until_complete(self._db.delete(table, id_value))

    def query_ai(self, natural_query: str) -> List[Dict[str, Any]]:
        return self._loop.run_until_complete(self._db.query_ai(natural_query))

    def sql(self, query: str) -> List[Dict[str, Any]]:
        return self._loop.run_until_complete(self._db.sql(query))

# Usage examples
async def example_async():
    """Async CRUD operations example"""
    async with OxideDb.connect('127.0.0.1:11597') as db:
        await db.authenticate('admin', 'password')
        db.use_db('test', 'test')

        # CREATE operations
        user_id = await db.insert('users', {
            'name': 'Alice Smith',
            'email': 'alice@example.com',
            'age': 28
        })
        print(f"Created user: {user_id}")

        # Batch insert
        users_data = [
            {'name': 'Bob Jones', 'email': 'bob@example.com', 'age': 35},
            {'name': 'Carol Brown', 'email': 'carol@example.com', 'age': 42}
        ]
        total_inserted = await db.insert_batch('users', users_data)
        print(f"Batch inserted: {total_inserted} users")

        # READ operations
        all_users = await db.find_all('users')
        print(f"All users: {all_users}")

        young_users = await db.select('users', 'age < 30')
        print(f"Young users: {young_users}")

        user_count = await db.count('users')
        print(f"Total users: {user_count}")

        # UPDATE operations
        updated = await db.update('users', 1, {'age': 29})
        print(f"Updated {updated} users")

        # DELETE operations
        deleted = await db.delete('users', 1)
        print(f"Deleted {deleted} users")

        # AI operations
        ai_results = await db.query_ai("show me all users sorted by age")
        print(f"AI query results: {ai_results}")

def example_sync():
    """Synchronous CRUD operations example"""
    with SyncOxideDb('127.0.0.1:11597') as db:
        db.authenticate('admin', 'password').use_db('test', 'test')

        # Same operations but synchronous
        user_id = db.insert('users', {'name': 'Sync User', 'email': 'sync@example.com'})
        print(f"Sync created user: {user_id}")

        users = db.select('users')
        print(f"Sync users: {users}")

### 3. JavaScript/TypeScript Client Library

```typescript
// oxidedb-client/src/index.ts
import * as grpc from '@grpc/grpc-js';
import { OxideDbServiceClient } from './generated/oxidedb_grpc_pb';
import {
    LoginRequest, LoginResponse, QueryRequest, QueryResponse,
    QueryMode, CreateDatabaseRequest, DeleteDatabaseRequest
} from './generated/oxidedb_pb';

export interface OxideDbConfig {
    address?: string;
    timeout?: number;
}

export class OxideDbError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'OxideDbError';
    }
}

export class OxideDb {
    private client: OxideDbServiceClient;
    private token?: string;
    private namespace?: string;
    private database?: string;

    constructor(config: OxideDbConfig = {}) {
        const address = config.address || '127.0.0.1:11597';
        this.client = new OxideDbServiceClient(address, grpc.credentials.createInsecure());
    }

    // Authentication
    async authenticate(username: string, password: string): Promise<OxideDb> {
        return new Promise((resolve, reject) => {
            const request = new LoginRequest();
            request.setUsername(username);
            request.setPassword(password);

            this.client.login(request, (error, response) => {
                if (error) {
                    reject(new OxideDbError(`Authentication failed: ${error.message}`));
                    return;
                }

                if (!response.getSuccess()) {
                    reject(new OxideDbError(`Authentication failed: ${response.getError()}`));
                    return;
                }

                this.token = response.getToken();
                resolve(this);
            });
        });
    }

    // Context selection
    useDb(namespace: string, database: string): OxideDb {
        this.namespace = namespace;
        this.database = database;
        return this;
    }

    // CREATE Operations
    async insert(table: string, data: Record<string, any>): Promise<number> {
        const sql = this.buildInsertSql(table, data);
        const result = await this.executeSql(sql);
        return result.getRowsAffected();
    }

    async insertBatch(table: string, data: Record<string, any>[]): Promise<number> {
        let totalAffected = 0;
        for (const record of data) {
            totalAffected += await this.insert(table, record);
        }
        return totalAffected;
    }

    async createTable(table: string, schema: Record<string, string>): Promise<void> {
        const sql = this.buildCreateTableSql(table, schema);
        await this.executeSql(sql);
    }

    // READ Operations
    async select(table: string, conditions?: string, options?: {
        limit?: number;
        orderBy?: string;
        offset?: number;
    }): Promise<Record<string, any>[]> {
        let sql = `SELECT * FROM ${table}`;
        
        if (conditions) {
            sql += ` WHERE ${conditions}`;
        }
        
        if (options?.orderBy) {
            sql += ` ORDER BY ${options.orderBy}`;
        }
        
        if (options?.limit) {
            sql += ` LIMIT ${options.limit}`;
        }
        
        if (options?.offset) {
            sql += ` OFFSET ${options.offset}`;
        }

        const result = await this.executeSql(sql);
        return this.extractDataArray(result);
    }

    async findById(table: string, id: any): Promise<Record<string, any> | null> {
        const condition = `id = ${this.formatValue(id)}`;
        const results = await this.select(table, condition, { limit: 1 });
        return results.length > 0 ? results[0] : null;
    }

    async findOne(table: string, conditions: string): Promise<Record<string, any> | null> {
        const results = await this.select(table, conditions, { limit: 1 });
        return results.length > 0 ? results[0] : null;
    }

    async findAll(table: string, conditions?: string): Promise<Record<string, any>[]> {
        return this.select(table, conditions);
    }

    async count(table: string, conditions?: string): Promise<number> {
        let sql = `SELECT COUNT(*) as count FROM ${table}`;
        if (conditions) {
            sql += ` WHERE ${conditions}`;
        }

        const result = await this.executeSql(sql);
        const data = this.extractDataArray(result);
        return data.length > 0 ? data[0].count : 0;
    }

    // UPDATE Operations
    async update(table: string, id: any, data: Record<string, any>): Promise<number> {
        const sql = this.buildUpdateSql(table, id, data);
        const result = await this.executeSql(sql);
        return result.getRowsAffected();
    }

    async updateWhere(table: string, conditions: string, data: Record<string, any>): Promise<number> {
        const sql = this.buildUpdateWhereSql(table, conditions, data);
        const result = await this.executeSql(sql);
        return result.getRowsAffected();
    }

    async upsert(table: string, id: any, data: Record<string, any>): Promise<number> {
        const existing = await this.findById(table, id);
        if (existing) {
            return this.update(table, id, data);
        } else {
            const insertData = { ...data, id };
            return this.insert(table, insertData);
        }
    }

    // DELETE Operations
    async delete(table: string, id: any): Promise<number> {
        const condition = `id = ${this.formatValue(id)}`;
        return this.deleteWhere(table, condition);
    }

    async deleteWhere(table: string, conditions: string): Promise<number> {
        const sql = `DELETE FROM ${table} WHERE ${conditions}`;
        const result = await this.executeSql(sql);
        return result.getRowsAffected();
    }

    async dropTable(table: string): Promise<void> {
        const sql = `DROP TABLE ${table}`;
        await this.executeSql(sql);
    }

    // AI Operations
    async queryAi(naturalQuery: string): Promise<Record<string, any>[]> {
        const result = await this.executeQuery(naturalQuery, QueryMode.AI);
        return this.extractDataArray(result);
    }

    async explainAi(queryResult: Record<string, any>[]): Promise<string> {
        const aiQuery = `Explain this data: ${JSON.stringify(queryResult)}`;
        const result = await this.queryAi(aiQuery);
        return JSON.stringify(result);
    }

    // Raw SQL
    async sql(query: string): Promise<Record<string, any>[]> {
        const result = await this.executeSql(query);
        return this.extractDataArray(result);
    }

    // Private helper methods
    private async executeSql(query: string): Promise<QueryResponse> {
        return this.executeQuery(query, QueryMode.SQL);
    }

    private async executeQuery(query: string, mode: QueryMode): Promise<QueryResponse> {
        return new Promise((resolve, reject) => {
            if (!this.token) {
                reject(new OxideDbError('Not authenticated'));
                return;
            }

            if (!this.namespace || !this.database) {
                reject(new OxideDbError('Namespace and database must be set'));
                return;
            }

            const request = new QueryRequest();
            request.setToken(this.token);
            request.setQuery(query);
            request.setMode(mode);
            request.setNamespace(this.namespace);
            request.setDatabase(this.database);

            this.client.executeQuery(request, (error, response) => {
                if (error) {
                    reject(new OxideDbError(`Query failed: ${error.message}`));
                    return;
                }

                if (!response.getSuccess()) {
                    reject(new OxideDbError(`Query failed: ${response.getError()}`));
                    return;
                }

                resolve(response);
            });
        });
    }

    private extractDataArray(response: QueryResponse): Record<string, any>[] {
        // Convert protobuf response to JavaScript objects
        // Implementation depends on the specific data format
        return []; // Placeholder implementation
    }

    private buildInsertSql(table: string, data: Record<string, any>): string {
        const columns = Object.keys(data);
        const values = columns.map(col => this.formatValue(data[col]));
        return `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${values.join(', ')})`;
    }

    private buildUpdateSql(table: string, id: any, data: Record<string, any>): string {
        const updates = Object.entries(data)
            .map(([col, val]) => `${col} = ${this.formatValue(val)}`);
        return `UPDATE ${table} SET ${updates.join(', ')} WHERE id = ${this.formatValue(id)}`;
    }

    private buildUpdateWhereSql(table: string, conditions: string, data: Record<string, any>): string {
        const updates = Object.entries(data)
            .map(([col, val]) => `${col} = ${this.formatValue(val)}`);
        return `UPDATE ${table} SET ${updates.join(', ')} WHERE ${conditions}`;
    }

    private buildCreateTableSql(table: string, schema: Record<string, string>): string {
        const columns = Object.entries(schema)
            .map(([name, typeDef]) => `${name} ${typeDef}`);
        return `CREATE TABLE ${table} (${columns.join(', ')})`;
    }

    private formatValue(value: any): string {
        if (typeof value === 'string') {
            return `'${value.replace(/'/g, "''")}'`;
        } else if (typeof value === 'number' || typeof value === 'boolean') {
            return String(value);
        } else if (value === null || value === undefined) {
            return 'NULL';
        } else {
            return `'${String(value)}'`;
        }
    }

    // Cleanup
    close(): void {
        this.client.close();
    }
}

// Usage examples
async function exampleUsage() {
    const db = new OxideDb({ address: '127.0.0.1:11597' });
    
    try {
        // Authentication and context
        await db.authenticate('admin', 'password');
        db.useDb('test', 'test');

        // CRUD operations
        const userId = await db.insert('users', {
            name: 'John Doe',
            email: 'john@example.com',
            age: 30
        });
        console.log('Created user:', userId);

        const users = await db.findAll('users');
        console.log('All users:', users);

        const updated = await db.update('users', userId, { age: 31 });
        console.log('Updated users:', updated);

        const deleted = await db.delete('users', userId);
        console.log('Deleted users:', deleted);

        // AI query
        const aiResults = await db.queryAi('show me all users sorted by age');
        console.log('AI results:', aiResults);

    } finally {
        db.close();
    }
}

// React Hook example
import { useState, useEffect } from 'react';

export function useOxideDb(config: OxideDbConfig) {
    const [db, setDb] = useState<OxideDb | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const client = new OxideDb(config);
        setDb(client);

        return () => {
            client.close();
        };
    }, [config]);

    const connect = async (username: string, password: string, namespace: string, database: string) => {
        if (!db) return;

        try {
            await db.authenticate(username, password);
            db.useDb(namespace, database);
            setIsConnected(true);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Connection failed');
            setIsConnected(false);
        }
    };

    return {
        db,
        isConnected,
        error,
        connect,
        // Convenience methods
        insert: db?.insert.bind(db),
        select: db?.select.bind(db),
        update: db?.update.bind(db),
        delete: db?.delete.bind(db),
        queryAi: db?.queryAi.bind(db),
        sql: db?.sql.bind(db),
    };
}
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

<<<<<<< HEAD
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
=======
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
>>>>>>> 8d1390ea25de9b9f8dd6fc7f7d2f3a1adda86bdf
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

<<<<<<< HEAD
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
=======
# Batch insert
batch_result = await (db
    .insert("products")
    .batch()
    .add_row({"name": "Product A", "price": 19.99})
    .add_row({"name": "Product B", "price": 29.99})
    .add_row({"name": "Product C", "price": 39.99})
    .on_duplicate_key_update()
    .execute())
>>>>>>> 8d1390ea25de9b9f8dd6fc7f7d2f3a1adda86bdf
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

<<<<<<< HEAD
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
=======
// Batch insert
const batchResult = await db
    .insert("products")
    .batch()
    .addRow({ name: "Product A", price: 19.99 })
    .addRow({ name: "Product B", price: 29.99 })
    .addRow({ name: "Product C", price: 39.99 })
    .onDuplicateKeyUpdate()
    .execute();
>>>>>>> 8d1390ea25de9b9f8dd6fc7f7d2f3a1adda86bdf
```

#### READ Operations with Chaining

<<<<<<< HEAD
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
=======
>>>>>>> 8d1390ea25de9b9f8dd6fc7f7d2f3a1adda86bdf
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
