# OxideDB - LLM-Powered Database with SQLite & gRPC

OxideDB (formerly CortexDB) is a powerful database system that combines SQLite with LLM capabilities, allowing you to query databases using both SQL and natural language. It uses high-performance gRPC protocol for client communication, providing efficient binary serialization and strong typing.

## Features

- **Dual Query Modes**: Execute raw SQL or use natural language queries
- **Multi-tenant Architecture**: Support for namespaces and multiple databases
- **Authentication & Authorization**: JWT-based auth with user-based namespace access
- **LLM Integration**: Uses OpenAI API for natural language to SQL conversion
- **gRPC Protocol**: High-performance binary protocol with Protocol Buffers
- **Interactive CLI**: Rich command-line interface with context switching
- **Client Libraries**: Knex.js-inspired SDKs for multiple programming languages

## Architecture Overview

### Protocol Support
- **gRPC**: High-performance binary protocol with Protocol Buffers (Port 11597)
- **CLI**: Interactive command-line interface with context switching

### Query Modes
1. **SQL Mode**: Direct SQL execution against SQLite databases
2. **AI Mode**: Natural language queries converted to SQL via LLM

### SQL Capabilities

OxideDB supports full SQLite functionality including:

#### Data Definition Language (DDL)
```sql
-- Create tables
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_username ON users(username);
CREATE UNIQUE INDEX idx_email ON users(email);

-- Alter tables
ALTER TABLE users ADD COLUMN last_login DATETIME;
ALTER TABLE users RENAME TO app_users;

-- Drop objects
DROP TABLE IF EXISTS temp_table;
DROP INDEX IF EXISTS idx_old_column;
```

#### Data Manipulation Language (DML)
```sql
-- Insert data
INSERT INTO users (username, email) VALUES ('john_doe', 'john@example.com');
INSERT INTO users (username, email) VALUES 
    ('jane_smith', 'jane@example.com'),
    ('bob_wilson', 'bob@example.com');

-- Update data
UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = 'john_doe';
UPDATE users SET email = 'newemail@example.com' WHERE id = 1;

-- Delete data
DELETE FROM users WHERE last_login IS NULL;
DELETE FROM users WHERE created_at < '2024-01-01';
```

#### Data Query Language (DQL)
```sql
-- Basic queries
SELECT * FROM users;
SELECT username, email FROM users WHERE created_at > '2024-01-01';

-- Joins
SELECT u.username, p.title 
FROM users u 
LEFT JOIN posts p ON u.id = p.user_id;

-- Aggregations
SELECT COUNT(*) as user_count FROM users;
SELECT DATE(created_at) as date, COUNT(*) as daily_users 
FROM users 
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- Subqueries
SELECT * FROM users 
WHERE id IN (SELECT user_id FROM posts WHERE status = 'published');

-- Window functions
SELECT username, 
       ROW_NUMBER() OVER (ORDER BY created_at) as user_rank,
       LAG(created_at) OVER (ORDER BY created_at) as prev_user_date
FROM users;

-- Common Table Expressions (CTEs)
WITH active_users AS (
    SELECT * FROM users WHERE last_login > DATE('now', '-30 days')
)
SELECT COUNT(*) FROM active_users;
```

#### Advanced SQL Features
```sql
-- JSON support
SELECT json_extract(metadata, '$.preferences.theme') as theme
FROM user_settings;

-- Full-text search (if FTS enabled)
SELECT * FROM documents WHERE documents MATCH 'search term';

-- Transactions
BEGIN TRANSACTION;
INSERT INTO users (username, email) VALUES ('new_user', 'new@example.com');
UPDATE user_stats SET total_users = total_users + 1;
COMMIT;

-- Views
CREATE VIEW active_users AS
SELECT * FROM users WHERE last_login > DATE('now', '-30 days');

-- Triggers
CREATE TRIGGER update_user_stats 
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;
```

## gRPC API

OxideDB provides a high-performance gRPC API defined in the Protocol Buffers schema. All client communication uses gRPC for optimal performance and type safety.

### Service Overview

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

### Core gRPC Methods

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

### Client Library Usage Examples

#### Rust Example
```rust
use oxidedb_client::OxideDb;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = OxideDb::connect("127.0.0.1:11597")
        .await?
        .authenticate("username", "password")
        .await?
        .use_db("namespace", "database");

    // Knex-style queries
    let users = db.table("users")
        .select(&["id", "name", "email"])
        .where_("age", ">", 18)
        .order_by_desc("created_at")
        .limit(10)
        .execute()
        .await?;

    // AI queries
    let ai_results = db.ai()
        .query("Show me all users who joined this month")
        .await?;

    println!("Users: {:?}", users);
    Ok(())
}
```

#### Python Example
```python
import asyncio
from oxidedb_client import OxideDb

async def main():
    async with OxideDb.connect('127.0.0.1:11597') as db:
        await db.authenticate('username', 'password')
        db.use_db('namespace', 'database')
        
        # Knex-style queries
        users = await db('users').select(['id', 'name', 'email']).where('age', '>', 18).execute()
        
        # AI queries
        ai_results = await db.ai('Show me all users who joined this month')
        
        print(f"Users: {users}")

if __name__ == "__main__":
    asyncio.run(main())
```

#### JavaScript/TypeScript Example
```javascript
import { OxideDb } from 'oxidedb-client';

async function main() {
    const db = new OxideDb({ address: '127.0.0.1:11597' });
    
    try {
        await db.authenticate('username', 'password');
        db.useDb('namespace', 'database');
        
        // Knex-style queries
        const users = await db('users')
            .select(['id', 'name', 'email'])
            .where('age', '>', 18)
            .orderBy('created_at', 'desc')
            .limit(10);
        
        // AI queries
        const aiResults = await db.ai().query('Show me all users who joined this month');
        
        console.log('Users:', users);
    } finally {
        db.close();
    }
}

main();
```

## Setup and Running

### Environment Variables

Set up environment variables in `.env`:

```env
OPENAI_API_KEY="your-openai-api-key"
LLM_API="https://api.openai.com/v1"
LLM_MODEL="gpt-4"
JWT_SECRET="your-secret-key"
DATABASE_PATH="./data"
GRPC_PORT="11597"
ROOT_USERNAME="root"
ROOT_PASSWORD="root"
DEBUG_MODE="false"
```

### Build and Run

```bash
# Build the project
cargo build --release

# Run gRPC server (default mode)
cargo run

# Run gRPC server explicitly
cargo run grpc

# Run interactive CLI
cargo run cli
```

### Running Modes

#### 1. gRPC Server Mode (Default)

```bash
./target/release/oxidedb
# or
./target/release/oxidedb grpc
# or
cargo run grpc
```

Starts gRPC server on port 11597

#### 2. Interactive CLI Mode

```bash
./target/release/oxidedb cli
# or
cargo run cli
```

Starts interactive CLI interface with context switching capabilities

## Architecture

- **Namespace Isolation**: Each namespace gets its own directory
- **Database Separation**: Each database is a separate SQLite file
- **Thread Safety**: Connections are managed with mutexes
- **Authentication**: JWT tokens with namespace-based authorization

## Example Usage

### Using Client Libraries

#### Basic CRUD Operations

```rust
use oxidedb_client::OxideDb;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect and authenticate
    let db = OxideDb::connect("127.0.0.1:11597")
        .await?
        .authenticate("demo", "demo123")
        .await?
        .use_db("demo", "test");

    // Create table
    db.schema()
        .create_table("users", |table| {
            table.increments("id");
            table.string("name").not_nullable();
            table.string("email").unique();
            table.timestamps();
        })
        .execute()
        .await?;

    // Insert data - Knex style
    db.table("users")
        .insert(serde_json::json!({
            "name": "John Doe",
            "email": "john@example.com"
        }))
        .execute()
        .await?;

    // Query data - Knex style  
    let users = db.table("users")
        .select(&["id", "name", "email"])
        .where_("name", "=", "John Doe")
        .execute()
        .await?;

    // AI query
    let ai_results = db.ai()
        .query("Show me all users")
        .await?;

    println!("Users: {:?}", users);
    println!("AI Results: {:?}", ai_results);

    Ok(())
}
```

#### Python Example

```python
import asyncio
from oxidedb_client import OxideDb

async def main():
    # Connect and authenticate
    async with OxideDb.connect('127.0.0.1:11597') as db:
        await db.authenticate('demo', 'demo123')
        db.use_db('demo', 'test')

        # Create table
        await db.schema.create_table('users', lambda table: (
            table.increments('id'),
            table.string('name').not_nullable(),
            table.string('email').unique(),
            table.timestamps()
        ))

        # Insert data
        await db('users').insert({
            'name': 'John Doe',
            'email': 'john@example.com'
        })

        # Query data
        users = await db('users').select(['id', 'name', 'email']).where('name', '=', 'John Doe')

        # AI query
        ai_results = await db.ai('Show me all users')

        print(f'Users: {users}')
        print(f'AI Results: {ai_results}')

if __name__ == "__main__":
    asyncio.run(main())
```

#### JavaScript Example

```javascript
import { OxideDb } from 'oxidedb-client';

async function main() {
    const db = new OxideDb({ address: '127.0.0.1:11597' });
    
    try {
        // Connect and authenticate
        await db.authenticate('demo', 'demo123');
        db.useDb('demo', 'test');

        // Create table
        await db.schema.createTable('users', function (table) {
            table.increments('id');
            table.string('name').notNullable();
            table.string('email').unique();
            table.timestamps();
        });

        // Insert data
        await db('users').insert({
            name: 'John Doe',
            email: 'john@example.com'
        });

        // Query data
        const users = await db('users')
            .select(['id', 'name', 'email'])
            .where('name', '=', 'John Doe');

        // AI query
        const aiResults = await db.ai().query('Show me all users');

        console.log('Users:', users);
        console.log('AI Results:', aiResults);
    } finally {
        db.close();
    }
}

main().catch(console.error);
```

### CLI Usage

```bash
# Start interactive CLI
cargo run cli

# Once in CLI:
> auth demo demo123
> use demo test
> sql CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)
> sql INSERT INTO users (name, email) VALUES ("John Doe", "john@example.com")
> ai Show me all users
> sql SELECT * FROM users WHERE name = "John Doe"
```
