use crate::error::{CortexError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>
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
    api_key: String,
}

impl OpenAIClient {
    pub fn new(api_url: String, model: String, api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_url,
            model,
            api_key,
        }
    }

    pub async fn generate_sql(&self, natural_query: &str, schema_info: &str) -> Result<String> {
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
            messages
        };

        let response = self
            .client
            .post(&format!("{}/chat/completions", self.api_url))
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
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
