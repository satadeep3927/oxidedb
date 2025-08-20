# Test register endpoint
Write-Host "=== Testing CortexDB API ==="
Write-Host ""

# Test 1: Register user (now requires root authentication via headers)
Write-Host "1. Testing user registration with root auth..."
$registerBody = @{
    username = "testuser"
    password = "password123"
    namespaces = @("demo", "test")
} | ConvertTo-Json

$headers = @{
    "Content-Type" = "application/json"
    "root-username" = "admin"
    "root-password" = "admin123"
}

try {
    $registerResponse = Invoke-RestMethod -Uri "http://localhost:3030/auth/register" -Method Post -Body $registerBody -Headers $headers
    Write-Host "✓ Registration successful:"
    $registerResponse | ConvertTo-Json -Depth 3
} catch {
    Write-Host "✗ Registration failed:"
    Write-Host $_.Exception.Message
}

Write-Host ""

# Test 2: Login
Write-Host "2. Testing user login..."
$loginBody = @{
    username = "testuser"
    password = "password123"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "http://localhost:3030/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
    Write-Host "✓ Login successful:"
    $loginResponse | ConvertTo-Json -Depth 3
    
    $token = $loginResponse.token
    Write-Host "Token extracted: $token"
    
    Write-Host ""
    
    # Test 3: Create table
    Write-Host "3. Testing SQL query (Create table)..."
    $createTableBody = @{
        query = "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT)"
        mode = "sql"
    } | ConvertTo-Json
    
    $headers = @{
        "Authorization" = "Bearer $token"
        "NS" = "demo"
        "DB" = "testdb"
        "Content-Type" = "application/json"
    }
    
    try {
        $createResponse = Invoke-RestMethod -Uri "http://localhost:3030/query" -Method Post -Body $createTableBody -Headers $headers
        Write-Host "✓ Table creation successful:"
        $createResponse | ConvertTo-Json -Depth 3
    } catch {
        Write-Host "✗ Table creation failed:"
        Write-Host $_.Exception.Message
    }
    
    Write-Host ""
    
    # Test 4: Insert data
    Write-Host "4. Testing SQL query (Insert data)..."
    $insertBody = @{
        query = "INSERT INTO products (name, price, category) VALUES ('Laptop', 999.99, 'Electronics')"
        mode = "sql"
    } | ConvertTo-Json
    
    try {
        $insertResponse = Invoke-RestMethod -Uri "http://localhost:3030/query" -Method Post -Body $insertBody -Headers $headers
        Write-Host "✓ Data insertion successful:"
        $insertResponse | ConvertTo-Json -Depth 3
    } catch {
        Write-Host "✗ Data insertion failed:"
        Write-Host $_.Exception.Message
    }
    
    Write-Host ""
    
    # Test 5: Select data
    Write-Host "5. Testing SQL query (Select data)..."
    $selectBody = @{
        query = "SELECT * FROM products"
        mode = "sql"
    } | ConvertTo-Json
    
    try {
        $selectResponse = Invoke-RestMethod -Uri "http://localhost:3030/query" -Method Post -Body $selectBody -Headers $headers
        Write-Host "✓ Data selection successful:"
        $selectResponse | ConvertTo-Json -Depth 3
    } catch {
        Write-Host "✗ Data selection failed:"
        Write-Host $_.Exception.Message
    }
    
} catch {
    Write-Host "✗ Login failed:"
    Write-Host $_.Exception.Message
}

Write-Host ""
Write-Host "=== Test completed ==="
