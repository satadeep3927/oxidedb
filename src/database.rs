use crate::models::DatabaseInfo;
use crate::error::Result;
use rusqlite::Connection;
use serde_json::{Value, Map};
use std::path::Path;
use std::fs;
use std::sync::Mutex;

pub struct Database {
    #[allow(dead_code)]
    pub info: DatabaseInfo,
    connection: Mutex<Connection>,
}

impl Database {
    pub fn new(info: DatabaseInfo) -> Result<Self> {
        // Ensure directory exists
        if let Some(parent) = Path::new(&info.path).parent() {
            fs::create_dir_all(parent)?;
        }
        
        let connection = Connection::open(&info.path)?;
        
        Ok(Database {
            info,
            connection: Mutex::new(connection),
        })
    }
    
    pub fn execute_query(&self, query: &str) -> Result<Value> {
        let query = query.trim();
        
        if query.to_uppercase().starts_with("SELECT") || 
           query.to_uppercase().starts_with("WITH") ||
           query.to_uppercase().starts_with("PRAGMA") {
            self.execute_select(query)
        } else {
            self.execute_non_select(query)
        }
    }
    
    fn execute_select(&self, query: &str) -> Result<Value> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(query)?;
        let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        
        let rows = stmt.query_map([], |row| {
            let mut map = Map::new();
            for (i, column_name) in column_names.iter().enumerate() {
                let value: Value = match row.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(i) => Value::Number(i.into()),
                    rusqlite::types::ValueRef::Real(r) => {
                        Value::Number(serde_json::Number::from_f64(r).unwrap_or(0.into()))
                    },
                    rusqlite::types::ValueRef::Text(s) => {
                        Value::String(String::from_utf8_lossy(s).to_string())
                    },
                    rusqlite::types::ValueRef::Blob(b) => {
                        Value::String(format!("BLOB({} bytes)", b.len()))
                    },
                };
                map.insert(column_name.clone(), value);
            }
            Ok(Value::Object(map))
        })?;
        
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        
        Ok(Value::Array(results))
    }
    
    fn execute_non_select(&self, query: &str) -> Result<Value> {
        let conn = self.connection.lock().unwrap();
        let changes = conn.execute(query, [])?;
        let last_insert_id = conn.last_insert_rowid();
        
        let mut result = Map::new();
        result.insert("changes".to_string(), Value::Number(changes.into()));
        result.insert("last_insert_id".to_string(), Value::Number(last_insert_id.into()));
        
        Ok(Value::Object(result))
    }
    
    pub fn get_schema_info(&self) -> Result<String> {
        let conn = self.connection.lock().unwrap();
        let tables_query = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";
        let mut stmt = conn.prepare(tables_query)?;
        let table_rows = stmt.query_map([], |row| {
            Ok(row.get::<_, String>(0)?)
        })?;
        
        let mut schema_info = String::new();
        schema_info.push_str("Database Schema:\n");
        
        for table_result in table_rows {
            let table_name = table_result?;
            schema_info.push_str(&format!("\nTable: {}\n", table_name));
            
            let columns_query = format!("PRAGMA table_info({})", table_name);
            let mut col_stmt = conn.prepare(&columns_query)?;
            let column_rows = col_stmt.query_map([], |row| {
                let name: String = row.get(1)?;
                let data_type: String = row.get(2)?;
                let not_null: bool = row.get(3)?;
                let pk: bool = row.get(5)?;
                Ok((name, data_type, not_null, pk))
            })?;
            
            for col_result in column_rows {
                let (name, data_type, not_null, pk) = col_result?;
                let mut col_info = format!("  - {} ({})", name, data_type);
                if not_null { col_info.push_str(" NOT NULL"); }
                if pk { col_info.push_str(" PRIMARY KEY"); }
                schema_info.push_str(&format!("{}\n", col_info));
            }
        }
        
        Ok(schema_info)
    }
}
