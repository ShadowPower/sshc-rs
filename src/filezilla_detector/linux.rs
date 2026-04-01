use super::first_existing;
use std::path::PathBuf;

pub(super) fn detect() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    for binary in ["filezilla", "org.filezillaproject.Filezilla"] {
        if let Ok(path) = which::which(binary) {
            candidates.push(path);
        }
    }

    candidates.extend([
        PathBuf::from("/usr/bin/filezilla"),
        PathBuf::from("/usr/local/bin/filezilla"),
        PathBuf::from("/snap/bin/filezilla"),
        PathBuf::from("/var/lib/flatpak/exports/bin/org.filezillaproject.Filezilla"),
    ]);

    if let Some(home) = dirs::home_dir() {
        candidates.push(
            home.join(".local")
                .join("share")
                .join("flatpak")
                .join("exports")
                .join("bin")
                .join("org.filezillaproject.Filezilla"),
        );
    }

    first_existing(candidates)
}
