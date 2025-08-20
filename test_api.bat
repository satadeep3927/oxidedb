@echo off
REM CortexDB API Test Script for Windows
REM This script demonstrates the complete workflow of CortexDB

set BASE_URL=http://localhost:3030

echo === CortexDB API Test ===
echo.

REM 1. Register a new user
echo 1. Registering user...
curl -s -X POST "%BASE_URL%/auth/register" -H "Content-Type: application/json" -d "{\"username\": \"demo\", \"password\": \"demo123\", \"namespaces\": [\"demo\", \"test\"]}" > register_response.json
type register_response.json
echo.

REM 2. Login to get token
echo 2. Logging in...
curl -s -X POST "%BASE_URL%/auth/login" -H "Content-Type: application/json" -d "{\"username\": \"demo\", \"password\": \"demo123\"}" > login_response.json
type login_response.json
echo.

REM Extract token manually (you'll need to copy this from the output)
echo Please copy the token from the login response above and update the TOKEN variable in this script
set TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
echo.

REM 3. Create a table using SQL mode
echo 3. Creating table...
curl -s -X POST "%BASE_URL%/query" -H "Authorization: Bearer %TOKEN%" -H "NS: demo" -H "DB: testdb" -H "Content-Type: application/json" -d "{\"query\": \"CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT)\", \"mode\": \"sql\"}" > create_table.json
type create_table.json
echo.

REM 4. Insert sample data
echo 4. Inserting sample data...
curl -s -X POST "%BASE_URL%/query" -H "Authorization: Bearer %TOKEN%" -H "NS: demo" -H "DB: testdb" -H "Content-Type: application/json" -d "{\"query\": \"INSERT INTO products (name, price, category) VALUES ('Laptop', 999.99, 'Electronics')\", \"mode\": \"sql\"}" > insert1.json
curl -s -X POST "%BASE_URL%/query" -H "Authorization: Bearer %TOKEN%" -H "NS: demo" -H "DB: testdb" -H "Content-Type: application/json" -d "{\"query\": \"INSERT INTO products (name, price, category) VALUES ('Book', 19.99, 'Education')\", \"mode\": \"sql\"}" > insert2.json
curl -s -X POST "%BASE_URL%/query" -H "Authorization: Bearer %TOKEN%" -H "NS: demo" -H "DB: testdb" -H "Content-Type: application/json" -d "{\"query\": \"INSERT INTO products (name, price, category) VALUES ('Coffee Mug', 12.50, 'Home')\", \"mode\": \"sql\"}" > insert3.json

type insert1.json
type insert2.json  
type insert3.json
echo.

REM 5. Query using SQL mode
echo 5. Querying with SQL...
curl -s -X POST "%BASE_URL%/query" -H "Authorization: Bearer %TOKEN%" -H "NS: demo" -H "DB: testdb" -H "Content-Type: application/json" -d "{\"query\": \"SELECT * FROM products WHERE price > 15\", \"mode\": \"sql\"}" > sql_query.json
type sql_query.json
echo.

REM 6. Query using AI mode (natural language)
echo 6. Querying with AI (natural language)...
curl -s -X POST "%BASE_URL%/query" -H "Authorization: Bearer %TOKEN%" -H "NS: demo" -H "DB: testdb" -H "Content-Type: application/json" -d "{\"query\": \"Show me all products in the Electronics category\", \"mode\": \"ai\"}" > ai_query.json
type ai_query.json
echo.

echo === Test completed ===
pause
