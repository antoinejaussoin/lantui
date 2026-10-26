use crate::model::ColumnId;
use anyhow::Context;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnPref {
    pub id: ColumnId,
    pub visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_interval")]
    pub live_interval_secs: u64,
    #[serde(default = "default_sort")]
    pub sort_column: ColumnId,
    #[serde(default = "default_true")]
    pub sort_asc: bool,
    #[serde(default = "default_columns")]
    pub columns: Vec<ColumnPref>,
}

fn default_interval() -> u64 {
    15
}

fn default_sort() -> ColumnId {
    ColumnId::Ipv4
}

fn default_true() -> bool {
    true
}

fn default_columns() -> Vec<ColumnPref> {
    ColumnId::ALL
        .into_iter()
        .map(|id| ColumnPref {
            visible: ColumnId::DEFAULT_VISIBLE.contains(&id),
            id,
        })
        .collect()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            live_interval_secs: default_interval(),
            sort_column: default_sort(),
            sort_asc: true,
            columns: default_columns(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Self {
        match config_path() {
            Some(path) if path.exists() => fs::read_to_string(&path)
                .ok()
                .and_then(|raw| toml::from_str(&raw).ok())
                .map(Self::normalized)
                .unwrap_or_default(),
            _ => Self::default(),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = config_path().context("could not resolve config directory")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    fn normalized(mut self) -> Self {
        let mut seen = Vec::new();
        self.columns.retain(|col| {
            if seen.contains(&col.id) {
                false
            } else {
                seen.push(col.id);
                true
            }
        });
        for id in ColumnId::ALL {
            if !self.columns.iter().any(|col| col.id == id) {
                self.columns.push(ColumnPref {
                    visible: ColumnId::DEFAULT_VISIBLE.contains(&id),
                    id,
                });
            }
        }
        if self.live_interval_secs == 0 {
            self.live_interval_secs = 15;
        }
        self
    }

    pub fn visible_columns(&self) -> Vec<ColumnId> {
        self.columns
            .iter()
            .filter(|col| col.visible)
            .map(|col| col.id)
            .collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Labels {
    #[serde(default)]
    pub comments: BTreeMap<String, String>,
}

impl Labels {
    pub fn load() -> Self {
        match labels_path() {
            Some(path) if path.exists() => fs::read_to_string(&path)
                .ok()
                .and_then(|raw| toml::from_str(&raw).ok())
                .unwrap_or_default(),
            _ => Self::default(),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = labels_path().context("could not resolve config directory")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.comments.get(key).map(String::as_str)
    }

    pub fn set(&mut self, key: String, value: String) {
        if value.is_empty() {
            self.comments.remove(&key);
        } else {
            self.comments.insert(key, value);
        }
    }
}

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("dev", "lantui", "lantui")
}

fn config_path() -> Option<PathBuf> {
    project_dirs().map(|dirs| dirs.config_dir().join("config.toml"))
}

fn labels_path() -> Option<PathBuf> {
    project_dirs().map(|dirs| dirs.config_dir().join("labels.toml"))
}
