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

#### Query Messages
```protobuf
message QueryRequest {
  string token = 1;
  string query = 2;
  QueryMode mode = 3;
  string namespace = 4;
  string database = 5;
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
