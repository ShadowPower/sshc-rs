use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod other;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
use other as imp;
#[cfg(target_os = "windows")]
use windows as imp;

pub fn detect() -> Option<PathBuf> {
    imp::detect()
}

pub fn require_path() -> Result<PathBuf> {
    detect().ok_or_else(|| anyhow!("未能找到 FileZilla，请确认已安装或已加入 PATH"))
}

fn first_existing(candidates: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    let mut seen = HashSet::new();

    for path in candidates {
        let normalized = normalize_key(&path);
        if !seen.insert(normalized) {
            continue;
        }
        if is_existing_file(&path) {
            return Some(path);
        }
    }

    None
}

fn is_existing_file(path: &Path) -> bool {
    path.is_file()
}

fn normalize_key(path: &Path) -> String {
    #[cfg(windows)]
    {
        path.to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    #[cfg(not(windows))]
    {
        path.to_string_lossy().into_owned()
    }
}
