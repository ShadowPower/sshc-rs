use super::first_existing;
use std::path::PathBuf;

pub(super) fn detect() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(path) = which::which("filezilla") {
        candidates.push(path);
    }

    candidates.push(
        PathBuf::from("/Applications")
            .join("FileZilla.app")
            .join("Contents")
            .join("MacOS")
            .join("filezilla"),
    );

    if let Some(home) = dirs::home_dir() {
        candidates.push(
            home.join("Applications")
                .join("FileZilla.app")
                .join("Contents")
                .join("MacOS")
                .join("filezilla"),
        );
    }

    first_existing(candidates)
}
