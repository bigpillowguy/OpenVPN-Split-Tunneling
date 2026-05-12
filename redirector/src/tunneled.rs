use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Shared, mutable list of exe paths the user has marked as tunneled.
/// Proc-watcher reloads this from disk on its tick; the divert hot path
/// reads it on every PID-miss to decide whether to admit synchronously.
pub type TunneledPaths = Arc<RwLock<Vec<PathBuf>>>;

pub fn new() -> TunneledPaths {
    Arc::new(RwLock::new(Vec::new()))
}

pub fn replace(paths: &TunneledPaths, new_paths: Vec<PathBuf>) {
    *paths.write().unwrap() = new_paths;
}

pub fn matches(paths: &TunneledPaths, candidate: &Path) -> bool {
    let candidate_lower = candidate.to_string_lossy().to_lowercase();
    let guard = paths.read().unwrap();
    guard
        .iter()
        .any(|p| p.to_string_lossy().to_lowercase() == candidate_lower)
}

pub fn load_from_disk() -> Vec<PathBuf> {
    let Ok(appdata) = std::env::var("APPDATA") else {
        return Vec::new();
    };
    let config_path = PathBuf::from(&appdata)
        .join("VpnClient")
        .join("config.json");

    let Ok(bytes) = std::fs::read(&config_path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    let Some(apps) = json.get("tunneledApps").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    apps.iter()
        .filter_map(|app| {
            app.get("exePath")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .collect()
}
