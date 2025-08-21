use crate::error::{CortexError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use chrono::Utc;

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
}

impl OpenAIClient {
    pub fn new(api_url: String, model: String, copilot_token: String) -> Self {
        Self {
            client: Client::new(),
            api_url,
            model,
            copilot_token,
            api_key: Mutex::new(String::new()), // Initialize with empty API key
        }
    }

    pub fn extract_exp_value(&self) -> Option<i64> {
        let api_key = self.api_key.lock().ok()?;
        let pairs = api_key.split(";");
        for pair in pairs {
            if let Some((key, value)) = pair.split_once('=') {
                if key.trim() == "exp" {
                    return value.trim().parse::<i64>().ok();
                }
            }
        }
        None
    }

    pub fn is_token_valid(&self) -> bool {
        let api_key = match self.api_key.lock() {
            Ok(key) => key,
            Err(_) => return false,
        };
        
        if api_key.contains("exp") {
            if let Some(exp) = self.extract_exp_value() {
                let current_time = Utc::now().timestamp();
                return exp > current_time;
            }
        }
        false
    }

    pub async fn exchange_copilot_token(&self) -> Result<()> {
        if self.is_token_valid() {
            println!("Using cached Copilot token");
            return Ok(());
        }

        let response = self
            .client
            .get("https://api.github.com/copilot_internal/v2/token")
            .header("authorization", format!("token {}", self.copilot_token))
            .header("editor-version", "Neovim/0.6.1")
            .header("editor-plugin-version", "copilot.vim/1.16.0")
            .header("user-agent", "GithubCopilot/1.155.0")
            .send()
            .await?;
        if !response.status().is_success() {
            let error_text = response.text().await?;
            eprintln!("Failed to exchange Copilot token: {}", error_text);
            return Err(CortexError::InvalidRequest(format!(
                "Failed to exchange Copilot token: {}",
                error_text
            )));
        }
        let token_data: serde_json::Value = response.json().await?;
        if let Some(token) = token_data.get("token").and_then(|t| t
            .as_str())
        {
            if let Ok(mut api_key) = self.api_key.lock() {
                *api_key = token.to_string();
            }
            println!("Successfully exchanged Copilot token");
            return Ok(());
        } else {
            eprintln!("Invalid response from Copilot token exchange");
            return Err(CortexError::InvalidRequest(
                "Invalid response from Copilot token exchange".to_string(),
            ));
        }
    }

    pub async fn generate_sql(&self, natural_query: &str, schema_info: &str) -> Result<String> {
        self.exchange_copilot_token().await?;
        
        let system_prompt = format!(
            "You are a SQL expert. Convert natural language queries to SQL.
            
Database Schema:
{}

Rules:
1. Generate only valid SQLite syntax
2. Return only the SQL query, no explanations
3. Use proper table and column names from the schema
4. Handle edge cases and invalid requests gracefully
5. For SELECT queries, always limit results to 100 rows unless specified otherwise",
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
                CortexError::InvalidRequest("Failed to acquire API key lock".to_string())
            })?;
            guard.clone()
        };

        let response = self
            .client
            .post(&format!("{}/chat/completions", self.api_url))
            .header("Authorization", &format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .header("editor-version", "Neovim/0.6.1")
            .header("editor-plugin-version", "copilot.vim/1.16.0")
            .header("user-agent", "GithubCopilot/1.155.0")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            eprintln!("OpenAI API error: {}", error_text);
            return Err(CortexError::InvalidRequest(format!(
                "LLM API error: {}",
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
            Ok(sql.to_string())
        } else {
            Err(CortexError::InvalidRequest(
                "No response from LLM".to_string(),
            ))
        }
    }
}
