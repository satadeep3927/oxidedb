#!/bin/bash

# CortexDB API Test Script
# This script demonstrates the complete workflow of CortexDB

BASE_URL="http://localhost:3030"

echo "=== CortexDB API Test ==="
echo

# 1. Register a new user
echo "1. Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "demo", "password": "demo123", "namespaces": ["demo", "test"]}')

echo "Register Response: $REGISTER_RESPONSE"
echo

# 2. Login to get token
echo "2. Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "demo", "password": "demo123"}')

echo "Login Response: $LOGIN_RESPONSE"

# Extract token from response (using jq if available, otherwise manual)
if command -v jq >/dev/null 2>&1; then
    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
else
    # Simple extraction without jq (not as reliable)
    TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
fi

echo "Token: $TOKEN"
echo

# 3. Create a table using SQL mode
echo "3. Creating table..."
CREATE_TABLE_RESPONSE=$(curl -s -X POST "$BASE_URL/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "NS: demo" \
  -H "DB: testdb" \
  -H "Content-Type: application/json" \
  -d '{"query": "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT)", "mode": "sql"}')

echo "Create Table Response: $CREATE_TABLE_RESPONSE"
echo

# 4. Insert sample data
echo "4. Inserting sample data..."
INSERT_RESPONSES=""

INSERT1=$(curl -s -X POST "$BASE_URL/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "NS: demo" \
  -H "DB: testdb" \
  -H "Content-Type: application/json" \
  -d '{"query": "INSERT INTO products (name, price, category) VALUES (\"Laptop\", 999.99, \"Electronics\")", "mode": "sql"}')

INSERT2=$(curl -s -X POST "$BASE_URL/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "NS: demo" \
  -H "DB: testdb" \
  -H "Content-Type: application/json" \
  -d '{"query": "INSERT INTO products (name, price, category) VALUES (\"Book\", 19.99, \"Education\")", "mode": "sql"}')

INSERT3=$(curl -s -X POST "$BASE_URL/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "NS: demo" \
  -H "DB: testdb" \
  -H "Content-Type: application/json" \
  -d '{"query": "INSERT INTO products (name, price, category) VALUES (\"Coffee Mug\", 12.50, \"Home\")", "mode": "sql"}')

echo "Insert 1: $INSERT1"
echo "Insert 2: $INSERT2"
echo "Insert 3: $INSERT3"
echo

# 5. Query using SQL mode
echo "5. Querying with SQL..."
SQL_QUERY_RESPONSE=$(curl -s -X POST "$BASE_URL/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "NS: demo" \
  -H "DB: testdb" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM products WHERE price > 15", "mode": "sql"}')

echo "SQL Query Response: $SQL_QUERY_RESPONSE"
echo

# 6. Query using AI mode (natural language)
echo "6. Querying with AI (natural language)..."
AI_QUERY_RESPONSE=$(curl -s -X POST "$BASE_URL/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "NS: demo" \
  -H "DB: testdb" \
  -H "Content-Type: application/json" \
  -d '{"query": "Show me all products in the Electronics category", "mode": "ai"}')

echo "AI Query Response: $AI_QUERY_RESPONSE"
echo

# 7. Another AI query
echo "7. Another AI query..."
AI_QUERY2_RESPONSE=$(curl -s -X POST "$BASE_URL/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "NS: demo" \
  -H "DB: testdb" \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the most expensive product?", "mode": "ai"}')

echo "AI Query 2 Response: $AI_QUERY2_RESPONSE"
echo

echo "=== Test completed ==="
