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

pub fn load_from_disk() -> anyhow::Result<Vec<PathBuf>> {
    use std::io::Read;
    let appdata = std::env::var("APPDATA")?;
    let config_path = PathBuf::from(&appdata)
        .join("VpnClient")
        .join("config.json");

    const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
    let file = std::fs::File::open(&config_path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_CONFIG_BYTES,
        "configuration file exceeds 4 MiB"
    );
    parse_config(&bytes)
}

pub fn load_initial() -> anyhow::Result<Vec<PathBuf>> {
    match load_from_disk() {
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(Vec::new())
        }
        result => result,
    }
}

fn parse_config(bytes: &[u8]) -> anyhow::Result<Vec<PathBuf>> {
    use anyhow::{bail, Context};
    let json: serde_json::Value = serde_json::from_slice(bytes)?;
    let apps = json
        .get("tunneledApps")
        .and_then(|v| v.as_array())
        .context("tunneledApps must be an array")?;
    if apps.len() > 4096 {
        bail!("too many tunneled applications");
    }
    let mut paths = Vec::new();
    for app in apps {
        let path = app
            .get("exePath")
            .and_then(|v| v.as_str())
            .context("exePath must be a string")?;
        if path.trim().is_empty() || path.len() > 32768 {
            bail!("invalid executable path");
        }
        if !paths
            .iter()
            .any(|p: &PathBuf| p.to_string_lossy().eq_ignore_ascii_case(path))
        {
            paths.push(PathBuf::from(path));
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_config_is_not_an_empty_policy() {
        for bytes in [
            b"{".as_slice(),
            br#"{}"#,
            br#"{"tunneledApps":null}"#,
            br#"{"tunneledApps":[{"exePath":4}]}"#,
        ] {
            assert!(parse_config(bytes).is_err());
        }
        assert!(parse_config(br#"{"tunneledApps":[]}"#).unwrap().is_empty());
    }
    #[test]
    fn config_deduplicates_paths() {
        assert_eq!(
            parse_config(
                br#"{"tunneledApps":[{"exePath":"C:\\App.exe"},{"exePath":"c:\\app.exe"}]}"#
            )
            .unwrap()
            .len(),
            1
        );
    }
}
