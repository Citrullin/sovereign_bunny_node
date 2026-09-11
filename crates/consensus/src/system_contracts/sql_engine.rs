//! Pure Rust Relational SQL Engine & Precompile for DAO & Contract Accounts.
//!
//! Provides relational table query and execution (`SELECT`, `INSERT`, `CREATE TABLE`)
//! against a contract's local account-lattice state. Computes deterministic table
//! state roots verified against the contract's CAR Slot 0x07 (`app.dao_anchor`).

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A row in a relational table represented as column-name -> string value.
pub type SqlRow = HashMap<String, String>;

/// A relational table stored in a contract's account register.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelationalTable {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<SqlRow>,
}

impl RelationalTable {
    /// Creates a new table with column definitions.
    #[must_use]
    pub fn new(name: &str, columns: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            columns,
            rows: Vec::new(),
        }
    }

    /// Computes the deterministic BLAKE3 state root of this table.
    #[must_use]
    pub fn compute_table_root(&self) -> B256 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"sql.table.root.v1");
        hasher.update(self.name.as_bytes());
        for col in &self.columns {
            hasher.update(col.as_bytes());
        }
        for row in &self.rows {
            // Deterministic row digest (columns sorted)
            let mut sorted_keys: Vec<&String> = row.keys().collect();
            sorted_keys.sort();
            for k in sorted_keys {
                hasher.update(k.as_bytes());
                if let Some(v) = row.get(k) {
                    hasher.update(v.as_bytes());
                }
            }
        }
        B256::from_slice(hasher.finalize().as_bytes())
    }
}

/// Relational Database Schema Catalog for a DAO or Contract account.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractSqlDatabase {
    pub tables: HashMap<String, RelationalTable>,
}

impl ContractSqlDatabase {
    /// Computes the composite state root of all tables in this contract's database.
    #[must_use]
    pub fn compute_state_root(&self) -> B256 {
        if self.tables.is_empty() {
            return B256::ZERO;
        }
        let mut table_roots: Vec<B256> = self.tables.values().map(RelationalTable::compute_table_root).collect();
        table_roots.sort();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"sql.db.composite.root.v1");
        for r in table_roots {
            hasher.update(r.as_slice());
        }
        B256::from_slice(hasher.finalize().as_bytes())
    }

    /// Executes a SQL query against this contract database.
    /// Supports `SELECT`, `INSERT INTO`, `CREATE TABLE`.
    pub fn execute_query(&mut self, query: &str) -> Result<SqlQueryResult, String> {
        let trimmed = query.trim();
        let upper = trimmed.to_uppercase();

        if upper.starts_with("CREATE TABLE") {
            self.execute_create_table(trimmed)
        } else if upper.starts_with("INSERT INTO") {
            self.execute_insert(trimmed)
        } else if upper.starts_with("SELECT") {
            self.execute_select(trimmed)
        } else {
            Err(format!("Unsupported SQL syntax: '{}'", trimmed))
        }
    }

    fn execute_create_table(&mut self, query: &str) -> Result<SqlQueryResult, String> {
        // Syntax: CREATE TABLE <name> (<col1>, <col2>, ...)
        let open_paren = query.find('(').ok_or("Missing '(' in CREATE TABLE")?;
        let close_paren = query.rfind(')').ok_or("Missing ')' in CREATE TABLE")?;
        let prefix = &query[..open_paren];
        let parts: Vec<&str> = prefix.split_whitespace().collect();
        if parts.len() < 3 {
            return Err("Invalid CREATE TABLE syntax".to_string());
        }
        let table_name = parts[2].trim_matches('`').to_string();

        let cols_part = &query[open_paren + 1..close_paren];
        let columns: Vec<String> = cols_part
            .split(',')
            .map(|col_def| {
                let def_parts: Vec<&str> = col_def.trim().split_whitespace().collect();
                def_parts.first().copied().unwrap_or("col").trim_matches('`').to_string()
            })
            .collect();

        self.tables.insert(table_name.clone(), RelationalTable::new(&table_name, columns));
        let new_root = self.compute_state_root();

        Ok(SqlQueryResult {
            rows_affected: 1,
            columns: vec!["status".to_string()],
            rows: vec![HashMap::from([("status".to_string(), format!("Table '{}' created", table_name))])],
            new_state_root: new_root,
        })
    }

    fn execute_insert(&mut self, query: &str) -> Result<SqlQueryResult, String> {
        // Syntax: INSERT INTO <name> VALUES ('v1', 'v2', ...)
        let upper = query.to_uppercase();
        let values_idx = upper.find("VALUES").ok_or("Missing VALUES clause in INSERT INTO")?;
        let table_part = &query[..values_idx];
        let parts: Vec<&str> = table_part.split_whitespace().collect();
        if parts.len() < 3 {
            return Err("Invalid INSERT INTO syntax".to_string());
        }
        let table_name = parts[2].trim_matches('`').to_string();

        let open_paren = query[values_idx..].find('(').ok_or("Missing '(' in VALUES")? + values_idx;
        let close_paren = query[values_idx..].rfind(')').ok_or("Missing ')' in VALUES")? + values_idx;
        let vals_part = &query[open_paren + 1..close_paren];
        let values: Vec<String> = vals_part
            .split(',')
            .map(|v| v.trim().trim_matches('\'').trim_matches('"').to_string())
            .collect();

        let table = self.tables.get_mut(&table_name).ok_or_else(|| format!("Table '{}' not found", table_name))?;
        let mut row = HashMap::new();
        for (i, col) in table.columns.iter().enumerate() {
            let val = values.get(i).cloned().unwrap_or_default();
            row.insert(col.clone(), val);
        }
        table.rows.push(row);
        let new_root = self.compute_state_root();

        Ok(SqlQueryResult {
            rows_affected: 1,
            columns: vec!["status".to_string()],
            rows: vec![HashMap::from([("status".to_string(), "1 row inserted".to_string())])],
            new_state_root: new_root,
        })
    }

    fn execute_select(&self, query: &str) -> Result<SqlQueryResult, String> {
        // Syntax: SELECT <cols> FROM <name> [WHERE <col> = <val>]
        let upper = query.to_uppercase();
        let from_idx = upper.find("FROM").ok_or("Missing FROM clause in SELECT")?;
        let table_part = &query[from_idx + 4..].trim();
        let table_and_where: Vec<&str> = table_part.split_whitespace().collect();
        if table_and_where.is_empty() {
            return Err("Invalid SELECT FROM syntax".to_string());
        }
        let table_name = table_and_where[0].trim_matches('`').to_string();

        let table = self.tables.get(&table_name).ok_or_else(|| format!("Table '{}' not found", table_name))?;

        let where_idx = upper.find("WHERE");
        let (filter_col, filter_val) = if let Some(w_pos) = where_idx {
            let cond_str = query[w_pos + 5..].trim();
            if let Some(eq_pos) = cond_str.find('=') {
                let col = cond_str[..eq_pos].trim().trim_matches('`').to_string();
                let val = cond_str[eq_pos + 1..].trim().trim_matches('\'').trim_matches('"').to_string();
                (Some(col), Some(val))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let mut matched_rows = Vec::new();
        for row in &table.rows {
            if let (Some(col), Some(val)) = (&filter_col, &filter_val) {
                if let Some(actual) = row.get(col) {
                    if actual == val {
                        matched_rows.push(row.clone());
                    }
                }
            } else {
                matched_rows.push(row.clone());
            }
        }

        Ok(SqlQueryResult {
            rows_affected: matched_rows.len(),
            columns: table.columns.clone(),
            rows: matched_rows,
            new_state_root: self.compute_state_root(),
        })
    }
}

/// Result of a SQL execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlQueryResult {
    pub rows_affected: usize,
    pub columns: Vec<String>,
    pub rows: Vec<SqlRow>,
    pub new_state_root: B256,
}
