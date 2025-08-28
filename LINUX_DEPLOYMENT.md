# OxideDB Linux Deployment Guide

## Building for Linux

### Option 1: On Linux System (Recommended)

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd oxidedb
   ```

2. **Run the build script:**
   ```bash
   chmod +x build-linux.sh
   ./build-linux.sh
   ```

3. **Install the binary:**
   ```bash
   sudo cp dist/oxidedb /usr/local/bin/
   sudo chmod +x /usr/local/bin/oxidedb
   ```

### Option 2: Using Docker

1. **Build and run with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

2. **Or build Docker image manually:**
   ```bash
   docker build -t oxidedb .
   docker run -d -p 11597:11597 -v $(pwd)/data:/data oxidedb
   ```

### Option 3: GitHub Actions (Automated)

Push your code to GitHub and the workflow will automatically build Linux binaries for:
- x86_64-unknown-linux-gnu (standard Linux)
- x86_64-unknown-linux-musl (static binary)
- aarch64-unknown-linux-gnu (ARM64/Apple Silicon)

## Configuration

1. **Create environment file:**
   ```bash
   cp .env.example .env
   nano .env
   ```

2. **Set required environment variables:**
   ```env
   LLM_API_KEY=your_gemini_api_key_here
   JWT_SECRET=your_jwt_secret_here
   DATABASE_PATH=./data
   ROOT_USERNAME=admin
   ROOT_PASSWORD=admin123
   ```

## Running as a Service (systemd)

1. **Create service file:**
   ```bash
   sudo nano /etc/systemd/system/oxidedb.service
   ```

2. **Add service configuration:**
   ```ini
   [Unit]
   Description=OxideDB LLM-powered Database Server
   After=network.target
   
   [Service]
   Type=simple
   User=oxidedb
   Group=oxidedb
   WorkingDirectory=/opt/oxidedb
   ExecStart=/usr/local/bin/oxidedb
   Restart=always
   RestartSec=10
   Environment=RUST_LOG=info
   EnvironmentFile=/opt/oxidedb/.env
   
   [Install]
   WantedBy=multi-user.target
   ```

3. **Create user and directories:**
   ```bash
   sudo useradd -r -s /bin/false oxidedb
   sudo mkdir -p /opt/oxidedb/data
   sudo chown -R oxidedb:oxidedb /opt/oxidedb
   sudo cp .env /opt/oxidedb/
   ```

4. **Enable and start service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable oxidedb
   sudo systemctl start oxidedb
   sudo systemctl status oxidedb
   ```

## Nginx Reverse Proxy (Optional)

1. **Install Nginx:**
   ```bash
   sudo apt install nginx
   ```

2. **Create Nginx configuration:**
   ```bash
   sudo nano /etc/nginx/sites-available/oxidedb
   ```

3. **Add configuration:**
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:3030;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

4. **Enable site:**
   ```bash
   sudo ln -s /etc/nginx/sites-available/oxidedb /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

## Testing the Deployment

```bash
# Check if service is running
curl http://localhost:3030/health

# Test registration (replace with your actual root credentials)
curl -X POST http://localhost:3030/auth/register \
  -H "Content-Type: application/json" \
  -H "root-username: admin" \
  -H "root-password: admin123" \
  -d '{"username": "testuser", "password": "password123", "namespaces": ["demo"]}'

# Test login
curl -X POST http://localhost:3030/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "password123"}'
```

## Troubleshooting

1. **Check logs:**
   ```bash
   sudo journalctl -u oxidedb -f
   ```

2. **Check file permissions:**
   ```bash
   ls -la /opt/oxidedb/
   ```

3. **Verify environment variables:**
   ```bash
   sudo systemctl show oxidedb --property=Environment
   ```

## Security Considerations

1. **Firewall setup:**
   ```bash
   sudo ufw allow 22/tcp
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

2. **Change default credentials in `.env` file**

3. **Use HTTPS in production with SSL certificates**

4. **Regularly update the system and oxidedb**
