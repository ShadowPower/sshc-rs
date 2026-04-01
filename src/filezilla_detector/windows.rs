use super::first_existing;
use std::path::{Path, PathBuf};
use winreg::HKEY;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

const EXE_NAME: &str = "filezilla.exe";
const APP_PATHS_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\filezilla.exe";
const MUI_CACHE_KEY: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
const APP_COMPAT_STORE_KEY: &str =
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store";
const UNINSTALL_KEY_PATHS: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
];

pub(super) fn detect() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    candidates.extend(detect_from_app_paths());
    candidates.extend(detect_from_uninstall());
    candidates.extend(detect_from_mui_cache());
    candidates.extend(detect_from_app_compat_store());

    if let Ok(path) = which::which(EXE_NAME).or_else(|_| which::which("filezilla")) {
        candidates.push(path);
    }

    candidates.extend(program_files_candidates());

    if let Some(local_data_dir) = dirs::data_local_dir() {
        candidates.push(
            local_data_dir
                .join("Programs")
                .join("FileZilla FTP Client")
                .join(EXE_NAME),
        );
        candidates.push(local_data_dir.join("FileZilla FTP Client").join(EXE_NAME));
    }

    first_existing(candidates)
}

fn detect_from_app_paths() -> Vec<PathBuf> {
    [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER]
        .into_iter()
        .filter_map(|root| read_app_path(root))
        .collect()
}

fn read_app_path(root: HKEY) -> Option<PathBuf> {
    let key = RegKey::predef(root)
        .open_subkey_with_flags(APP_PATHS_KEY, KEY_READ)
        .ok()?;

    if let Ok(raw_path) = key.get_value::<String, _>("") {
        let path = extract_executable_path(&raw_path);
        if path.is_file() {
            return Some(path);
        }
    }

    let install_dir = key.get_value::<String, _>("Path").ok()?;
    let candidate = PathBuf::from(install_dir).join(EXE_NAME);
    candidate.is_file().then_some(candidate)
}

fn detect_from_uninstall() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let base = RegKey::predef(root);
        for subkey_path in UNINSTALL_KEY_PATHS {
            let uninstall_key = match base.open_subkey_with_flags(subkey_path, KEY_READ) {
                Ok(key) => key,
                Err(_) => continue,
            };

            for entry in uninstall_key.enum_keys().flatten() {
                let app_key = match uninstall_key.open_subkey_with_flags(&entry, KEY_READ) {
                    Ok(key) => key,
                    Err(_) => continue,
                };

                let display_name = app_key
                    .get_value::<String, _>("DisplayName")
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let key_name = entry.to_ascii_lowercase();

                if !display_name.contains("filezilla") && !key_name.contains("filezilla") {
                    continue;
                }

                if let Ok(install_location) = app_key.get_value::<String, _>("InstallLocation") {
                    candidates.push(PathBuf::from(install_location).join(EXE_NAME));
                }

                if let Ok(display_icon) = app_key.get_value::<String, _>("DisplayIcon") {
                    candidates.push(extract_executable_path(&display_icon));
                }
            }
        }
    }

    candidates
}

fn detect_from_mui_cache() -> Vec<PathBuf> {
    let key =
        match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(MUI_CACHE_KEY, KEY_READ) {
            Ok(key) => key,
            Err(_) => return Vec::new(),
        };

    key.enum_values()
        .flatten()
        .filter_map(|(name, _)| candidate_from_history_entry(&name))
        .collect()
}

fn detect_from_app_compat_store() -> Vec<PathBuf> {
    let key = match RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(APP_COMPAT_STORE_KEY, KEY_READ)
    {
        Ok(key) => key,
        Err(_) => return Vec::new(),
    };

    key.enum_values()
        .flatten()
        .filter_map(|(name, _)| candidate_from_history_entry(&name))
        .collect()
}

fn candidate_from_history_entry(entry: &str) -> Option<PathBuf> {
    let cleaned = strip_history_suffix(entry);
    let path = extract_executable_path(cleaned);
    has_filezilla_name(&path).then_some(path)
}

fn strip_history_suffix(entry: &str) -> &str {
    entry
        .trim()
        .trim_end_matches(".FriendlyAppName")
        .trim_end_matches(".ApplicationCompany")
}

fn has_filezilla_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.eq_ignore_ascii_case(EXE_NAME))
        .unwrap_or(false)
}

fn program_files_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for env_name in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        let Some(base_dir) = std::env::var_os(env_name) else {
            continue;
        };

        candidates.push(
            PathBuf::from(&base_dir)
                .join("FileZilla FTP Client")
                .join(EXE_NAME),
        );
    }

    candidates
}

fn extract_executable_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim().trim_matches('"');
    let lower = trimmed.to_ascii_lowercase();

    if let Some(index) = lower.find(".exe") {
        return PathBuf::from(&trimmed[..index + 4]);
    }

    PathBuf::from(trimmed)
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_from_history_entry, detect, detect_from_uninstall, extract_executable_path,
        read_app_path, strip_history_suffix,
    };
    use std::path::Path;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    #[test]
    fn extracts_display_icon_path_with_arguments() {
        let path =
            extract_executable_path(r#""C:\Program Files\FileZilla FTP Client\FileZilla.exe",0"#);
        assert_eq!(
            path,
            Path::new(r"C:\Program Files\FileZilla FTP Client\FileZilla.exe")
        );
    }

    #[test]
    fn strips_known_mui_suffixes() {
        assert_eq!(
            strip_history_suffix(r"C:\Tools\FileZilla.exe.FriendlyAppName"),
            r"C:\Tools\FileZilla.exe"
        );
        assert_eq!(
            strip_history_suffix(r"C:\Tools\FileZilla.exe.ApplicationCompany"),
            r"C:\Tools\FileZilla.exe"
        );
    }

    #[test]
    fn filters_non_filezilla_history_entries() {
        assert_eq!(
            candidate_from_history_entry(r"C:\Tools\Other.exe.FriendlyAppName"),
            None
        );
    }

    #[test]
    fn detects_real_installation_when_present() {
        let has_local_install = read_app_path(HKEY_LOCAL_MACHINE).is_some()
            || read_app_path(HKEY_CURRENT_USER).is_some()
            || detect_from_uninstall()
                .into_iter()
                .any(|path| path.is_file());

        if has_local_install {
            let detected = detect().expect("expected FileZilla path on this machine");
            assert!(detected.is_file());
            assert_eq!(
                detected
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.to_ascii_lowercase())
                    .as_deref(),
                Some("filezilla.exe")
            );
        }
    }
}
