use std::path::PathBuf;

pub(super) fn detect() -> Option<PathBuf> {
    which::which("filezilla").ok().map(PathBuf::from)
}
