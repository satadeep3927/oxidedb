use crate::database::Database;
use crate::error::Result;
use crate::models::DatabaseInfo;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct DatabaseManager {
    base_path: String,
    connections: Arc<Mutex<HashMap<String, Arc<Database>>>>,
}

impl DatabaseManager {
    pub fn new(base_path: &str) -> Result<Self> {
        std::fs::create_dir_all(base_path)?;

        Ok(DatabaseManager {
            base_path: base_path.to_string(),
            connections: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn get_database(&self, namespace: &str, database: &str) -> Result<Arc<Database>> {
        let key = format!("{}:{}", namespace, database);

        // Check if connection already exists
        {
            let connections = self.connections.lock().unwrap();
            if let Some(db) = connections.get(&key) {
                return Ok(db.clone());
            }
        }

        // Create new connection
        let db_path = self.get_database_path(namespace, database);
        let db_info = DatabaseInfo {
            namespace: namespace.to_string(),
            database: database.to_string(),
            path: db_path,
        };

        let database = Arc::new(Database::new(db_info)?);

        // Store the connection
        {
            let mut connections = self.connections.lock().unwrap();
            connections.insert(key, database.clone());
        }

        Ok(database)
    }

    fn get_database_path(&self, namespace: &str, database: &str) -> String {
        let mut path = PathBuf::from(&self.base_path);
        path.push(namespace.to_uppercase());
        std::fs::create_dir_all(&path).ok();
        path.push(database.to_uppercase());
        path.to_string_lossy().to_string()
    }

    #[allow(dead_code)]
    pub fn list_namespaces(&self) -> Result<Vec<String>> {
        let base_path = PathBuf::from(&self.base_path);
        let mut namespaces = Vec::new();

        if base_path.exists() {
            for entry in std::fs::read_dir(&base_path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        namespaces.push(name.to_string());
                    }
                }
            }
        }

        Ok(namespaces)
    }

    #[allow(dead_code)]
    pub fn list_databases(&self, namespace: &str) -> Result<Vec<String>> {
        let mut path = PathBuf::from(&self.base_path);
        path.push(namespace);

        let mut databases = Vec::new();

        if path.exists() {
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        // Database files are now uppercase without extensions
                        databases.push(name.to_string());
                    }
                }
            }
        }

        Ok(databases)
    }

    #[allow(dead_code)]
    pub fn create_namespace(&self, namespace: &str) -> Result<()> {
        let mut path = PathBuf::from(&self.base_path);
        path.push(namespace);
        std::fs::create_dir_all(&path)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn delete_database(&self, namespace: &str, database: &str) -> Result<()> {
        let key = format!("{}:{}", namespace, database);

        // Remove from connections
        {
            let mut connections = self.connections.lock().unwrap();
            connections.remove(&key);
        }

        // Delete the file
        let db_path = self.get_database_path(namespace, database);
        if std::path::Path::new(&db_path).exists() {
            std::fs::remove_file(&db_path)?;
        }

        Ok(())
    }
}
