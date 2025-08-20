# CortexDB - LLM-Powered Database with SQLite

CortexDB is a powerful database system that combines SQLite with LLM capabilities, allowing you to query databases using both SQL and natural language.

## Features

- **Dual Query Modes**: Execute raw SQL or use natural language queries
- **Multi-tenant Architecture**: Support for namespaces and multiple databases
- **Authentication & Authorization**: JWT-based auth with user-based namespace access
- **LLM Integration**: Uses Gemini 2.5 Flash for natural language to SQL conversion
- **RESTful API**: Simple HTTP interface for all operations

## API Endpoints

### Authentication

#### Register User
```
POST /auth/register
Content-Type: application/json

{
  "username": "testuser",
  "password": "password123",
  "namespaces": ["company", "personal"]
}
```

#### Login
```
POST /auth/login
Content-Type: application/json

{
  "username": "testuser",
  "password": "password123"
}
```

Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user_id": "uuid-here",
  "namespaces": ["company", "personal"]
}
```

### Query Execution

#### SQL Mode
```
POST /query
Authorization: Bearer <token>
NS: company
DB: products
Content-Type: application/json

{
  "query": "SELECT * FROM products WHERE price > 100",
  "mode": "sql"
}
```

#### AI Mode (Natural Language)
```
POST /query
Authorization: Bearer <token>
NS: company
DB: products
Content-Type: application/json

{
  "query": "Show me all products that cost more than 100 dollars",
  "mode": "ai"
}
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "Laptop",
      "price": 999.99
    }
  ],
  "error": null,
  "execution_time_ms": 45
}
```

## Setup and Running

1. Set up environment variables in `.env`:
```
LLM_API="https://generativelanguage.googleapis.com/v1beta/openai/"
LLM_MODEL="gemini-2.5-flash"
LLM_API_KEY="your-api-key"
JWT_SECRET="your-secret-key"
DATABASE_PATH="./data"
SERVER_PORT="3030"
```

2. Build and run:
```bash
cargo build --release
cargo run
```

## Architecture

- **Namespace Isolation**: Each namespace gets its own directory
- **Database Separation**: Each database is a separate SQLite file
- **Thread Safety**: Connections are managed with mutexes
- **Authentication**: JWT tokens with namespace-based authorization

## Example Usage

### Creating Sample Data

1. Register a user:
```bash
curl -X POST http://localhost:3030/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "demo", "password": "demo123", "namespaces": ["demo"]}'
```

2. Login:
```bash
curl -X POST http://localhost:3030/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "demo", "password": "demo123"}'
```

3. Create a table:
```bash
curl -X POST http://localhost:3030/query \
  -H "Authorization: Bearer <token>" \
  -H "NS: demo" \
  -H "DB: test" \
  -H "Content-Type: application/json" \
  -d '{"query": "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)", "mode": "sql"}'
```

4. Insert data:
```bash
curl -X POST http://localhost:3030/query \
  -H "Authorization: Bearer <token>" \
  -H "NS: demo" \
  -H "DB: test" \
  -H "Content-Type: application/json" \
  -d '{"query": "INSERT INTO users (name, email) VALUES (\"John Doe\", \"john@example.com\")", "mode": "sql"}'
```

5. Query with natural language:
```bash
curl -X POST http://localhost:3030/query \
  -H "Authorization: Bearer <token>" \
  -H "NS: demo" \
  -H "DB: test" \
  -H "Content-Type: application/json" \
  -d '{"query": "Show me all users", "mode": "ai"}'
```
