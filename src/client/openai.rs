use crate::error::{OxideError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Deserialize)]
struct Message {
    content: String,
}

pub struct OpenAIClient {
    client: Client,
    api_url: String,
    model: String,
    api_key: Mutex<String>,
    copilot_token: String,
    debug_mode: bool,
    last_token_refresh: Mutex<std::time::Instant>,
}

impl OpenAIClient {
    pub fn new(api_url: String, model: String, copilot_token: String, debug_mode: bool) -> Self {
        Self {
            client: Client::new(),
            api_url,
            model,
            copilot_token,
            api_key: Mutex::new(String::new()), // Initialize with empty API key
            debug_mode,
            last_token_refresh: Mutex::new(std::time::Instant::now() - Duration::from_secs(3600)), // Force refresh on first call
        }
    }

    pub fn is_token_valid(&self) -> bool {
        let api_key = match self.api_key.lock() {
            Ok(key) => key,
            Err(_) => return false,
        };

        if api_key.is_empty() {
            return false;
        }

        // Check if token was refreshed recently (within 50 minutes - tokens usually last 1 hour)
        let last_refresh = match self.last_token_refresh.lock() {
            Ok(time) => *time,
            Err(_) => return false,
        };

        let token_age = last_refresh.elapsed();
        token_age < Duration::from_secs(3000) // 50 minutes
    }

    pub async fn exchange_copilot_token(&self) -> Result<()> {
        if self.debug_mode {
            println!("Checking token validity...");
        }

        if self.is_token_valid() {
            if self.debug_mode {
                println!("Using cached token");
            }
            return Ok(());
        }

        if self.debug_mode {
            println!("Refreshing token...");
        }

        let token_request = async {
            let response = self
                .client
                .get("https://api.github.com/copilot_internal/v2/token")
                .header("authorization", format!("token {}", self.copilot_token))
                .header("editor-version", "Neovim/0.6.1")
                .header("editor-plugin-version", "copilot.vim/1.16.0")
                .header("user-agent", "GithubCopilot/1.155.0")
                .timeout(Duration::from_secs(10)) // Add timeout to the request itself
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                if self.debug_mode {
                    eprintln!(
                        "Failed to exchange token - Status: {}, Error: {}",
                        status, error_text
                    );
                }
                return Err(OxideError::InvalidRequest(format!(
                    "Failed to exchange token: {} - {}",
                    status, error_text
                )));
            }

            let token_data: serde_json::Value = response.json().await?;
            if let Some(token) = token_data.get("token").and_then(|t| t.as_str()) {
                if let Ok(mut api_key) = self.api_key.lock() {
                    *api_key = token.to_string();
                }
                // Update the refresh timestamp
                if let Ok(mut last_refresh) = self.last_token_refresh.lock() {
                    *last_refresh = std::time::Instant::now();
                }
                if self.debug_mode {
                    println!("Successfully exchanged token");
                }
                Ok(())
            } else {
                if self.debug_mode {
                    eprintln!("Invalid response from token exchange: no token field found");
                }
                Err(OxideError::InvalidRequest(
                    "Invalid response from token exchange".to_string(),
                ))
            }
        };

        // Add overall timeout for the entire operation
        match timeout(Duration::from_secs(15), token_request).await {
            Ok(result) => {
                if self.debug_mode {
                    println!("Token exchange operation completed");
                }
                result
            }
            Err(_) => {
                if self.debug_mode {
                    eprintln!("Token exchange timed out after 15 seconds");
                }
                Err(OxideError::InvalidRequest(
                    "Token exchange timed out".to_string(),
                ))
            }
        }
    }

    pub async fn generate_sql(&self, natural_query: &str, schema_info: &str) -> Result<String> {
        if self.debug_mode {
            println!("Starting SQL generation for query: {}", natural_query);
        }
        self.exchange_copilot_token().await?;

        if self.debug_mode {
            println!("Token exchange completed, generating SQL...");
        }

        let system_prompt = format!(
            "You are a SQL expert. Convert natural language queries to SQL.
            
Database Schema:
{}

Rules:
1. Generate only valid SQLite syntax
2. Return only the SQL query, no explanations
3. Use proper table and column names from the schema
4. Handle edge cases and invalid requests gracefully
5. For SELECT queries, always limit results to 100 rows unless specified otherwise
6. You may generate multiple SQL statements separated by semicolons when needed (e.g., creating multiple tables)
7. Each statement should be on its own line for clarity
8. Use proper SQL string escaping - escape single quotes by doubling them (e.g., 'Sorcerer''s Stone' not 'Sorcerer\\'s Stone')",
            schema_info
        );

        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: system_prompt,
            },
            ChatMessage {
                role: "user".to_string(),
                content: natural_query.to_string(),
            },
        ];

        let request = ChatRequest {
            model: self.model.clone(),
            messages,
        };

        let api_key = {
            let guard = self.api_key.lock().map_err(|_| {
                OxideError::InvalidRequest("Failed to acquire API key lock".to_string())
            })?;
            guard.clone()
        };

        let response = self
            .client
            .post(&format!("{}/chat/completions", self.api_url))
            .header("Authorization", &format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .header("editor-version", "vscode/1.103.1")
            .header("editor-plugin-version", "copilot.vim/1.16.0")
            .header("user-agent", "GithubCopilot/1.155.0")
            .timeout(Duration::from_secs(300)) // Add timeout for SQL generation
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            if self.debug_mode {
                eprintln!("Query Engine API error: {}", error_text);
            }
            return Err(OxideError::InvalidRequest(format!(
                "Query Engine API error: {}",
                error_text
            )));
        }

        let chat_response: ChatResponse = response.json().await?;

        if let Some(choice) = chat_response.choices.first() {
            let sql = choice.message.content.trim();
            // Clean up the SQL (remove markdown code blocks if present)
            let sql = sql
                .trim_start_matches("```sqlite")
                .trim_start_matches("```sql")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim();

            // Fix SQL string escaping issues
            let sql = self.fix_sql_escaping(sql);

            if self.debug_mode {
                println!("Generated SQL response: {}", sql);
            }

            Ok(sql.to_string())
        } else {
            Err(OxideError::InvalidRequest(
                "No response from Query Engine".to_string(),
            ))
        }
    }

    fn fix_sql_escaping(&self, sql: &str) -> String {
        // Fix single quote escaping in SQL strings
        // Replace \' with '' (proper SQLite escaping)
        sql.replace("\\'", "''")
    }
}
